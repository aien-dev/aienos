//! Host-testable CPU placement and fair run-queue policy.
//!
//! MADT efficiency classes use lower numbers for more efficient cores. This
//! module treats larger class numbers as faster cores and has no hardware
//! dependencies. A caller supplies the enabled CPU classes explicitly.

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskPriority {
    Background,
    Normal,
    Latency,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Task {
    pub id: u32,
    pub priority: TaskPriority,
    pub cpu: usize,
    pub ticks: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerError {
    NoCpus,
    Full,
    DuplicateTask,
    InvalidCpu,
}

/// Fixed-capacity scheduler. `CLASSES` maps CPU index to its MADT class.
/// Queue storage and task accounting are bounded by `TASKS`.
pub struct Scheduler<const CPUS: usize, const TASKS: usize> {
    classes: [u8; CPUS],
    tasks: [Option<Task>; TASKS],
    queues: [[Option<usize>; TASKS]; CPUS],
    queue_len: [usize; CPUS],
    cursor: usize,
}

impl<const CPUS: usize, const TASKS: usize> Scheduler<CPUS, TASKS> {
    pub const fn new(classes: [u8; CPUS]) -> Self {
        Self {
            classes,
            tasks: [None; TASKS],
            queues: [[None; TASKS]; CPUS],
            queue_len: [0; CPUS],
            cursor: 0,
        }
    }

    pub fn place(&self, priority: TaskPriority) -> Result<usize, SchedulerError> {
        if CPUS == 0 {
            return Err(SchedulerError::NoCpus);
        }
        let best_class = match priority {
            TaskPriority::Latency => *self.classes.iter().max().unwrap(),
            TaskPriority::Background => *self.classes.iter().min().unwrap(),
            TaskPriority::Normal => {
                let start = self.cursor % CPUS;
                return (0..CPUS)
                    .map(|offset| (start + offset) % CPUS)
                    .min_by_key(|cpu| self.queue_len[*cpu])
                    .ok_or(SchedulerError::NoCpus);
            }
        };
        let start = self.cursor % CPUS;
        for offset in 0..CPUS {
            let cpu = (start + offset) % CPUS;
            if self.classes[cpu] == best_class {
                return Ok(cpu);
            }
        }
        unreachable!()
    }

    pub fn enqueue(&mut self, id: u32, priority: TaskPriority) -> Result<usize, SchedulerError> {
        if self.tasks.iter().flatten().any(|task| task.id == id) {
            return Err(SchedulerError::DuplicateTask);
        }
        let slot = self
            .tasks
            .iter()
            .position(Option::is_none)
            .ok_or(SchedulerError::Full)?;
        let cpu = self.place(priority)?;
        self.cursor = (cpu + 1) % CPUS;
        let queue_slot = self.queue_len[cpu];
        self.queues[cpu][queue_slot] = Some(slot);
        self.queue_len[cpu] += 1;
        self.tasks[slot] = Some(Task {
            id,
            priority,
            cpu,
            ticks: 0,
        });
        Ok(cpu)
    }

    /// Account one tick on a CPU, choosing highest priority then least-served
    /// task. Equal tasks therefore share service evenly over repeated ticks.
    pub fn tick(&mut self, cpu: usize) -> Result<Option<u32>, SchedulerError> {
        if cpu >= CPUS {
            return Err(SchedulerError::InvalidCpu);
        }
        if self.queue_len[cpu] == 0 && !self.steal(cpu)? {
            return Ok(None);
        }
        let mut selected: Option<usize> = None;
        for &slot in self.queues[cpu][..self.queue_len[cpu]].iter().flatten() {
            let task = self.tasks[slot].expect("queued task exists");
            selected = match selected {
                None => Some(slot),
                Some(old) => {
                    let previous = self.tasks[old].expect("queued task exists");
                    if task.priority > previous.priority
                        || (task.priority == previous.priority && task.ticks < previous.ticks)
                    {
                        Some(slot)
                    } else {
                        Some(old)
                    }
                }
            };
        }
        if let Some(slot) = selected {
            let task = self.tasks[slot].as_mut().expect("queued task exists");
            task.ticks = task.ticks.saturating_add(1);
            Ok(Some(task.id))
        } else {
            Ok(None)
        }
    }

    /// Move the most-served eligible task from the longest queue, leaving
    /// high-priority work runnable there. Called automatically for idle CPUs.
    pub fn steal(&mut self, idle_cpu: usize) -> Result<bool, SchedulerError> {
        if idle_cpu >= CPUS {
            return Err(SchedulerError::InvalidCpu);
        }
        if self.queue_len[idle_cpu] != 0 {
            return Ok(false);
        }
        let mut donor = None;
        for cpu in 0..CPUS {
            if cpu != idle_cpu
                && self.queue_len[cpu] > 1
                && donor.is_none_or(|old| self.queue_len[cpu] > self.queue_len[old])
            {
                donor = Some(cpu);
            }
        }
        let Some(donor) = donor else { return Ok(false) };
        let mut candidate = None;
        for &slot in self.queues[donor][..self.queue_len[donor]].iter().flatten() {
            let task = self.tasks[slot].expect("queued task exists");
            candidate = match candidate {
                None => Some(slot),
                Some(old) => {
                    let prev = self.tasks[old].expect("queued task exists");
                    if task.priority < prev.priority
                        || (task.priority == prev.priority && task.ticks > prev.ticks)
                    {
                        Some(slot)
                    } else {
                        Some(old)
                    }
                }
            };
        }
        let slot = candidate.expect("non-empty donor");
        let pos = self.queues[donor][..self.queue_len[donor]]
            .iter()
            .position(|v| *v == Some(slot))
            .unwrap();
        for i in pos..self.queue_len[donor] - 1 {
            self.queues[donor][i] = self.queues[donor][i + 1];
        }
        self.queue_len[donor] -= 1;
        self.queues[idle_cpu][0] = Some(slot);
        self.queue_len[idle_cpu] = 1;
        self.tasks[slot].as_mut().expect("queued task exists").cpu = idle_cpu;
        Ok(true)
    }

    pub fn task(&self, id: u32) -> Option<Task> {
        self.tasks
            .iter()
            .flatten()
            .find(|task| task.id == id)
            .copied()
    }

    pub fn queue_len(&self, cpu: usize) -> Option<usize> {
        self.queue_len.get(cpu).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placement_uses_fast_cores_for_latency_and_efficient_for_background() {
        let mut s = Scheduler::<4, 8>::new([0, 0, 1, 1]);
        assert!(matches!(s.enqueue(1, TaskPriority::Latency), Ok(2 | 3)));
        assert!(matches!(s.enqueue(2, TaskPriority::Background), Ok(0 | 1)));
    }

    #[test]
    fn equal_priority_tasks_share_n_ticks_fairly() {
        let mut s = Scheduler::<1, 4>::new([0]);
        s.enqueue(1, TaskPriority::Normal).unwrap();
        s.enqueue(2, TaskPriority::Normal).unwrap();
        for _ in 0..20 {
            s.tick(0).unwrap();
        }
        assert_eq!(s.task(1).unwrap().ticks, 10);
        assert_eq!(s.task(2).unwrap().ticks, 10);
    }

    #[test]
    fn priority_prevents_basic_inversion() {
        let mut s = Scheduler::<1, 4>::new([0]);
        s.enqueue(1, TaskPriority::Background).unwrap();
        s.enqueue(2, TaskPriority::Latency).unwrap();
        assert_eq!(s.tick(0), Ok(Some(2)));
    }

    #[test]
    fn idle_cpu_steals_and_runs_work() {
        let mut s = Scheduler::<2, 4>::new([0, 1]);
        s.enqueue(1, TaskPriority::Background).unwrap();
        s.enqueue(2, TaskPriority::Background).unwrap();
        assert!(s.steal(1).unwrap());
        assert!(s.task(1).unwrap().cpu == 1 || s.task(2).unwrap().cpu == 1);
        assert!(s.tick(1).unwrap().is_some());
    }

    #[test]
    fn empty_queues_and_invalid_cpu_are_handled() {
        let mut s = Scheduler::<2, 2>::new([0, 1]);
        assert_eq!(s.tick(0), Ok(None));
        assert!(!s.steal(1).unwrap());
        assert_eq!(s.tick(2), Err(SchedulerError::InvalidCpu));
    }

    #[test]
    fn round_robin_placement_and_duplicate_rejection() {
        let mut s = Scheduler::<2, 4>::new([0, 0]);
        assert_eq!(s.enqueue(1, TaskPriority::Normal), Ok(0));
        assert_eq!(s.enqueue(2, TaskPriority::Normal), Ok(1));
        assert_eq!(
            s.enqueue(1, TaskPriority::Normal),
            Err(SchedulerError::DuplicateTask)
        );
    }
}

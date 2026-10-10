//! Choice between the f32 and the int8 activation dot path (aienos#34 L6-B,
//! qualification in `docs/l6b-int8-qualification.md`).
//!
//! The crate is `no_std` and `forbid(unsafe_code)`, so it cannot read CPU
//! registers. The caller detects CPU features and passes a [`Features`] value.
//! The host harness (`examples/l6_host.rs`) fills it from the Linux auxiliary
//! vector.
//!
//! Kernel hook point (not implemented here; kernel register reads go through
//! the manual-guard process): the native kernel must fill [`Features`] from
//! the AArch64 ID registers, `dotprod` from `ID_AA64ISAR0_EL1.DP` (field value
//! 1 or more) and `i8mm` from `ID_AA64ISAR1_EL1.I8MM` (field value 1 or more),
//! read at EL1 on the boot core and checked on every core that will decode.
//!
//! Rollback: [`INT8_PROMOTION_DEFAULT`] is `false`. With it `false` nothing
//! selects int8 unless the caller explicitly asks for it. On a host,
//! `AIENOS_DOT=f32` forces f32 regardless of features.

/// Build-time switch for the kernel. `false`: int8 is never chosen by feature
/// detection alone, the f32 path stays the default. Changing it to `true` is
/// the promotion, changing it back is the rollback.
pub const INT8_PROMOTION_DEFAULT: bool = false;

/// CPU features that make the int8 path fast (`sdot`/`udot` and `usdot`).
/// Supplied by the caller; this crate never probes the CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Features {
    /// Armv8.2 dot product (`HWCAP_ASIMDDP`, `ID_AA64ISAR0_EL1.DP`).
    pub dotprod: bool,
    /// Armv8.6 int8 matrix multiply (`HWCAP2_I8MM`, `ID_AA64ISAR1_EL1.I8MM`).
    pub i8mm: bool,
}

/// `HWCAP_ASIMDDP` in the Linux `AT_HWCAP` word (arm64).
pub const HWCAP_ASIMDDP: u64 = 1 << 20;
/// `HWCAP2_I8MM` in the Linux `AT_HWCAP2` word (arm64).
pub const HWCAP2_I8MM: u64 = 1 << 13;

impl Features {
    /// No feature present.
    pub const NONE: Features = Features {
        dotprod: false,
        i8mm: false,
    };

    /// Decode the arm64 Linux auxiliary-vector words `AT_HWCAP` and `AT_HWCAP2`.
    pub fn from_hwcap(hwcap: u64, hwcap2: u64) -> Self {
        Self {
            dotprod: hwcap & HWCAP_ASIMDDP != 0,
            i8mm: hwcap2 & HWCAP2_I8MM != 0,
        }
    }

    /// Both features present.
    pub fn both(&self) -> bool {
        self.dotprod && self.i8mm
    }
}

/// Which activation path the decoder runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DotPath {
    /// f32 activations (the default and the fallback).
    F32,
    /// Q8_K int8 activations with i32 dots.
    Int8,
}

impl DotPath {
    /// Selector with the build-time default ([`INT8_PROMOTION_DEFAULT`]).
    pub fn select(features: Features, requested: bool) -> Self {
        Self::select_with(features, requested, INT8_PROMOTION_DEFAULT)
    }

    /// Int8 only when the caller requests it, or when promotion is enabled and
    /// both features are present. Otherwise f32. An explicit request is
    /// honoured without the features: the int8 code is portable, only slower.
    pub fn select_with(features: Features, requested: bool, promotion: bool) -> Self {
        if requested || (promotion && features.both()) {
            DotPath::Int8
        } else {
            DotPath::F32
        }
    }

    /// Apply an operator setting (`AIENOS_DOT`) with the build-time default.
    pub fn resolve(features: Features, setting: DotSetting) -> Self {
        Self::resolve_with(features, setting, INT8_PROMOTION_DEFAULT)
    }

    /// `F32` forces f32 whatever the features and promotion say (the
    /// rollback). `Int8` forces int8. `Auto` runs the selector.
    pub fn resolve_with(features: Features, setting: DotSetting, promotion: bool) -> Self {
        match setting {
            DotSetting::F32 => DotPath::F32,
            DotSetting::Int8 => DotPath::Int8,
            DotSetting::Auto => Self::select_with(features, false, promotion),
        }
    }
}

/// The operator's choice (host: the `AIENOS_DOT` environment variable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DotSetting {
    /// Let the selector decide (variable unset or `auto`).
    Auto,
    /// Force f32, the rollback.
    F32,
    /// Force int8.
    Int8,
}

impl DotSetting {
    /// Parse the variable's value (`None` when unset). Unknown text is `None`
    /// so the caller can refuse it rather than guess.
    pub fn parse(value: Option<&str>) -> Option<Self> {
        match value {
            None | Some("auto") => Some(DotSetting::Auto),
            Some("f32") => Some(DotSetting::F32),
            Some("int8") => Some(DotSetting::Int8),
            Some(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: Features = Features {
        dotprod: false,
        i8mm: false,
    };
    const DOT_ONLY: Features = Features {
        dotprod: true,
        i8mm: false,
    };
    const MM_ONLY: Features = Features {
        dotprod: false,
        i8mm: true,
    };
    const BOTH: Features = Features {
        dotprod: true,
        i8mm: true,
    };

    #[test]
    fn select_matrix_all_combinations() {
        use DotPath::{Int8, F32};
        // (features, requested, promotion, expected)
        let rows: [(Features, bool, bool, DotPath); 16] = [
            (NONE, false, false, F32),
            (NONE, false, true, F32),
            (NONE, true, false, Int8),
            (NONE, true, true, Int8),
            (DOT_ONLY, false, false, F32),
            (DOT_ONLY, false, true, F32),
            (DOT_ONLY, true, false, Int8),
            (DOT_ONLY, true, true, Int8),
            (MM_ONLY, false, false, F32),
            (MM_ONLY, false, true, F32),
            (MM_ONLY, true, false, Int8),
            (MM_ONLY, true, true, Int8),
            (BOTH, false, false, F32),
            (BOTH, false, true, Int8),
            (BOTH, true, false, Int8),
            (BOTH, true, true, Int8),
        ];
        for (f, requested, promotion, want) in rows {
            assert_eq!(
                DotPath::select_with(f, requested, promotion),
                want,
                "features {f:?} requested {requested} promotion {promotion}"
            );
        }
    }

    #[test]
    fn features_from_hwcap_bits() {
        let dp = 1u64 << 20;
        let mm = 1u64 << 13;
        assert_eq!(Features::from_hwcap(0, 0), NONE);
        assert_eq!(Features::from_hwcap(dp, 0), DOT_ONLY);
        assert_eq!(Features::from_hwcap(0, mm), MM_ONLY);
        assert_eq!(Features::from_hwcap(dp, mm), BOTH);
        // The i8mm bit in AT_HWCAP (not AT_HWCAP2) and the dotprod bit in
        // AT_HWCAP2 mean something else and must not be read.
        assert_eq!(Features::from_hwcap(mm, dp), NONE);
        // Unrelated bits do not set anything.
        assert_eq!(Features::from_hwcap(!dp, !mm), NONE);
    }

    #[test]
    fn default_constant_off_and_auto_is_f32_with_features() {
        assert!(!core::hint::black_box(INT8_PROMOTION_DEFAULT));
        assert_eq!(DotPath::select(BOTH, false), DotPath::F32);
        assert_eq!(DotPath::resolve(BOTH, DotSetting::Auto), DotPath::F32);
        assert_eq!(DotPath::select(BOTH, true), DotPath::Int8);
    }

    #[test]
    fn rollback_setting_f32_forces_f32_with_all_features() {
        // AIENOS_DOT=f32: f32 with every feature present, promotion on or off.
        for promotion in [false, true] {
            assert_eq!(
                DotPath::resolve_with(BOTH, DotSetting::parse(Some("f32")).unwrap(), promotion),
                DotPath::F32
            );
        }
        // Auto with promotion on and features present is the only way to int8
        // without asking; the F32 setting overrides it.
        assert_eq!(
            DotPath::resolve_with(BOTH, DotSetting::Auto, true),
            DotPath::Int8
        );
        assert_eq!(
            DotPath::resolve_with(NONE, DotSetting::Int8, false),
            DotPath::Int8
        );
    }

    #[test]
    fn setting_parse() {
        assert_eq!(DotSetting::parse(None), Some(DotSetting::Auto));
        assert_eq!(DotSetting::parse(Some("auto")), Some(DotSetting::Auto));
        assert_eq!(DotSetting::parse(Some("f32")), Some(DotSetting::F32));
        assert_eq!(DotSetting::parse(Some("int8")), Some(DotSetting::Int8));
        assert_eq!(DotSetting::parse(Some("INT8")), None);
        assert_eq!(DotSetting::parse(Some("")), None);
        assert_eq!(DotSetting::parse(Some("i8")), None);
    }
}

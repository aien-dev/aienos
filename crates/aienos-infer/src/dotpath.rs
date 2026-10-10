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
        use DotPath::{F32, Int8};
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
        assert!(!INT8_PROMOTION_DEFAULT);
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

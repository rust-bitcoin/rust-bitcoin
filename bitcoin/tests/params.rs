use bitcoin::network::{params::Params, Network, TestnetVersion};

fn assert_params_eq(a: &Params, b: &Params) {
	assert_eq!(a.network, b.network);
	assert_eq!(a.bip16_time, b.bip16_time);
	assert_eq!(a.bip34_height, b.bip34_height);
	assert_eq!(a.bip65_height, b.bip65_height);
	assert_eq!(a.bip66_height, b.bip66_height);
	assert_eq!(a.rule_change_activation_threshold, b.rule_change_activation_threshold);
	assert_eq!(a.miner_confirmation_window, b.miner_confirmation_window);
	#[allow(deprecated)]
	{
		assert_eq!(a.pow_limit, b.pow_limit);
	}
	assert_eq!(a.max_attainable_target, b.max_attainable_target);
	assert_eq!(a.pow_target_spacing, b.pow_target_spacing);
	assert_eq!(a.pow_target_timespan, b.pow_target_timespan);
	assert_eq!(a.allow_min_difficulty_blocks, b.allow_min_difficulty_blocks);
	assert_eq!(a.no_pow_retargeting, b.no_pow_retargeting);
}

#[test]
fn new_returns_correct_predefined_params() {
	let cases = [
		(Network::Bitcoin, Params::MAINNET),
		(Network::Testnet(TestnetVersion::V3), Params::TESTNET3),
		(Network::Testnet(TestnetVersion::V4), Params::TESTNET4),
		(Network::Signet, Params::SIGNET),
		(Network::Regtest, Params::REGTEST),
	];

	for (network, expected) in cases {
		let got = Params::new(network);
		assert_params_eq(&got, &expected);
	}
}

#[test]
fn difficulty_adjustment_interval_matches_definition() {
	let predefined = [
		Params::MAINNET,
		Params::TESTNET3,
		Params::TESTNET4,
		Params::SIGNET,
		Params::REGTEST,
	];

	for params in &predefined {
		let want = u64::from(params.pow_target_timespan) / params.pow_target_spacing;
		assert_eq!(params.difficulty_adjustment_interval(), want);
	}
}

#[test]
fn conversions_work_as_documented() {
	let cases = [
		(Network::Bitcoin, Params::MAINNET),
		(Network::Testnet(TestnetVersion::V3), Params::TESTNET3),
		(Network::Testnet(TestnetVersion::V4), Params::TESTNET4),
		(Network::Signet, Params::SIGNET),
		(Network::Regtest, Params::REGTEST),
	];

	for (network, expected) in cases {
		// From<Network> for Params
		let from_value: Params = network.into();
		assert_params_eq(&from_value, &expected);

		// From<Network> for &'static Params
		let from_ref: &'static Params = network.into();
		assert_params_eq(from_ref, &expected);

		// AsRef<Params> for Network
		let as_ref_from_network: &Params = network.as_ref();
		assert_params_eq(as_ref_from_network, &expected);

		// AsRef<Params> for Params
		let as_ref_from_params: &Params = expected.as_ref();
		assert_params_eq(as_ref_from_params, &expected);
	}
}

#[test]
#[allow(deprecated)]
fn deprecated_alias_testnet_equals_testnet3() {
	assert_params_eq(&Params::TESTNET, &Params::TESTNET3);
} 
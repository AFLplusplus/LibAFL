use std::env;

use libafl_cc::{Configuration, LibtoolWrapper, ToolWrapper};

pub fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let mut cc = LibtoolWrapper::new();
        if let Some(code) = cc
            // silence the compiler wrapper output, needed for some configure scripts.
            .silence(true)
            .parse_args(&args)
            .expect("Failed to parse the command line")
            .add_configuration(Configuration::GenerateCoverageMap)
            .add_configuration(Configuration::Compound(vec![
                Configuration::GenerateCoverageMap,
                Configuration::CmpLog,
            ]))
            .add_configuration(Configuration::Compound(vec![
                Configuration::GenerateCoverageMap,
                Configuration::AddressSanitizer,
            ]))
            .add_configuration(Configuration::Compound(vec![
                Configuration::GenerateCoverageMap,
                Configuration::UndefinedBehaviorSanitizer,
            ]))
            .run()
            .expect("Failed to run the wrapped libtool")
        {
            std::process::exit(code);
        }
    } else {
        panic!("LibAFL libtool: No Arguments given");
    }
}

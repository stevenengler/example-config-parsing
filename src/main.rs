use std::collections::BTreeMap;

use clap::ArgEnum;
use clap::Clap;
use merge::Merge;
use once_cell::sync::Lazy;
use schemars::{schema_for, JsonSchema};
use serde::{Deserialize, Serialize};

fn main() {
    // get the cli options
    let opts: CliOptions = CliOptions::parse();
    println!("{:#?}", opts);

    let filename = if let Some(filename) = &opts.config {
        filename
    } else {
        return;
    };

    // read the config file
    let config_file: ConfigFileOptions =
        serde_yaml::from_reader(std::fs::File::open(filename).unwrap()).unwrap();
    println!("\n{:#?}", config_file);

    // combine the cli options and config file into the final config structure
    let config = ConfigOptions::new(&config_file, &opts);
    println!("\n{:#?}", config);
}

/// Help messages used by Clap for command line arguments, combining the doc string with
/// the Serde default.
static HELP_MSGS: Lazy<std::collections::HashMap<String, String>> = Lazy::new(|| {
    let mut defaults = std::collections::HashMap::<String, String>::new();
    defaults.extend(generate_help_strs(schema_for!(GeneralOptions)));
    defaults.extend(generate_help_strs(schema_for!(HostDefaultOptions)));
    defaults.extend(generate_help_strs(schema_for!(ExperimentalOptions)));
    defaults
});

#[derive(Debug, Clone, Clap)]
pub struct CliOptions {
    /// Path to the Shadow configuration file. Use '-' to read from stdin
    #[clap(required_unless_present_any(&["show-build-info", "shm-cleanup"]))]
    config: Option<String>,

    /// Pause to allow gdb to attach
    #[clap(long, short = 'g')]
    gdb: bool,

    /// Exit after running shared memory cleanup routine
    #[clap(long, exclusive(true))]
    shm_cleanup: bool,

    /// Exit after printing build information
    #[clap(long, exclusive(true))]
    show_build_info: bool,

    /// Print the final configuration
    #[clap(long)]
    show_config: bool,

    #[clap(flatten)]
    general: GeneralOptions,

    #[clap(flatten)]
    host_defaults: HostDefaultOptions,

    #[clap(flatten)]
    experimental: ExperimentalOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigFileOptions {
    general: GeneralOptions,

    #[serde(default)]
    host_defaults: HostDefaultOptions,

    #[serde(default)]
    experimental: ExperimentalOptions,

    topology: Topology,

    // we use a BTreeMap so that the hosts are sorted by their hostname (useful for determinism)
    hosts: BTreeMap<String, HostOptions>,
}

#[derive(Debug, Clone)]
pub struct ConfigOptions {
    general: GeneralOptions,

    experimental: ExperimentalOptions,

    topology: Topology,

    // we use a BTreeMap so that the hosts are sorted by their hostname (useful for determinism)
    hosts: BTreeMap<String, HostOptions>,
}

impl ConfigOptions {
    pub fn new(config_file: &ConfigFileOptions, options: &CliOptions) -> Self {
        let mut config_file = config_file.clone();

        // override config options with command line options
        config_file.general = GeneralOptions::merge(&options.general, &config_file.general);
        config_file.host_defaults =
            HostDefaultOptions::merge(&options.host_defaults, &config_file.host_defaults);
        config_file.experimental =
            ExperimentalOptions::merge(&options.experimental, &config_file.experimental);

        // copy the host defaults to all of the hosts
        for (_, host) in &mut config_file.hosts {
            host.options = HostDefaultOptions::merge(&host.options, &config_file.host_defaults);
        }

        Self {
            general: config_file.general.clone(),
            experimental: config_file.experimental.clone(),
            topology: config_file.topology.clone(),
            hosts: config_file.hosts.clone(),
        }
    }
}

// these must all be Option types since they aren't required by the CLI, even if they're
// required in the configuration file
#[derive(Debug, Clone, Clap, Serialize, Deserialize, Merge, JsonSchema)]
#[clap(help_heading = "(General) Override configuration file options")]
#[serde(deny_unknown_fields)]
pub struct GeneralOptions {
    /// The simulated time at which simulated processes are sent a SIGKILL signal
    #[clap(long, value_name = "seconds")]
    #[clap(about = HELP_MSGS.get("stop_time").unwrap())]
    stop_time: Option<u32>,

    /// Environment variables passed to all simulated processes (ex: "ENV\_A=1;ENV\_B=2")
    #[clap(long)]
    #[clap(about = HELP_MSGS.get("environment").unwrap())]
    environment: Option<String>,

    /// Initialize randomness for each thread using seed N
    #[clap(long, value_name = "N", next_line_help = true)]
    #[clap(about = HELP_MSGS.get("seed").unwrap())]
    #[serde(default = "default_some_0")]
    seed: Option<u32>,

    /// Run concurrently with N worker threads
    #[clap(long, short = 'w', value_name = "N", next_line_help = true)]
    #[clap(about = HELP_MSGS.get("workers").unwrap())]
    #[serde(default = "default_some_0")]
    workers: Option<u32>,

    #[clap(long, value_name = "seconds")]
    #[clap(about = HELP_MSGS.get("bootstrap_end_time").unwrap())]
    #[serde(default = "default_some_0")]
    bootstrap_end_time: Option<u32>,

    /// Log level of output written on stdout. If Shadow was built in release mode, then log
    /// messages at a level lower than 'info' will always be dropped
    #[clap(long, short = 'l', value_name = "LEVEL")]
    #[clap(about = HELP_MSGS.get("log_level").unwrap())]
    #[serde(default = "default_some_info")]
    log_level: Option<LogLevel>,

    /// Interval at which to print heartbeat messages
    #[clap(long, value_name = "seconds", next_line_help = true)]
    #[clap(about = HELP_MSGS.get("heartbeat_interval").unwrap())]
    #[serde(default = "default_some_1")]
    heartbeat_interval: Option<u32>,

    /// PATH to store simulation output
    #[clap(long, short = 'd', value_name = "PATH", next_line_help = true)]
    #[clap(about = HELP_MSGS.get("data_directory").unwrap())]
    #[serde(default = "default_data_directory")]
    data_directory: Option<String>,

    /// PATH to recursively copy during startup and use as the data-directory
    #[clap(long, short = 'e', value_name = "PATH")]
    #[clap(about = HELP_MSGS.get("template_directory").unwrap())]
    template_directory: Option<String>,
}

impl GeneralOptions {
    /// Replace unset (`None`) values of `base` with values from `default`.
    pub fn merge(base: &Self, default: &Self) -> Self {
        let mut base = base.clone();
        base.merge(default.clone());
        base
    }
}

#[derive(Debug, Clone, Clap, Serialize, Deserialize, Merge, JsonSchema)]
#[clap(
    help_heading = "(Experimental) Unstable and may change or be removed at any time, regardless of Shadow version"
)]
#[serde(default)]
pub struct ExperimentalOptions {
    /// Use the SCHED\_FIFO scheduler. Requires CAP\_SYS\_NICE. See sched(7), capabilities(7)
    #[clap(long, value_name = "bool")]
    #[clap(about = HELP_MSGS.get("set_sched_fifo").unwrap())]
    set_sched_fifo: Option<bool>,

    /// Disable performance workarounds for waitpid being O(n). Beneficial to disable if waitpid
    /// is patched to be O(1) or in some cases where it'd otherwise result in excessive detaching
    /// and reattaching
    #[clap(long, value_name = "bool")]
    #[clap(about = HELP_MSGS.get("disable_o_n_waitpid_workarounds").unwrap())]
    disable_o_n_waitpid_workarounds: Option<bool>,

    /// Send message to plugin telling it to stop spinning when a syscall blocks
    #[clap(long, value_name = "bool")]
    #[clap(about = HELP_MSGS.get("disable_explicit_block_message").unwrap())]
    disable_explicit_block_message: Option<bool>,

    /// Count the number of occurrences for individual syscalls
    #[clap(long, value_name = "bool")]
    #[clap(about = HELP_MSGS.get("enable_syscall_counters").unwrap())]
    enable_syscall_counters: Option<bool>,

    /// Disable counting object allocations and deallocations. If disabled, we will not be able to detect object memory leaks
    #[clap(long, value_name = "bool")]
    #[clap(about = HELP_MSGS.get("disable_object_counters").unwrap())]
    disable_object_counters: Option<bool>,

    /// Max number of iterations to busy-wait on ICP sempahore before blocking
    #[clap(long, value_name = "iterations")]
    #[clap(about = HELP_MSGS.get("preload_spin_max").unwrap())]
    preload_spin_max: Option<i32>,

    /// Maximum number of workers to allow to run at once
    #[clap(long)]
    #[clap(about = HELP_MSGS.get("max_concurrency").unwrap())]
    max_concurrency: Option<i32>,

    /// Disable the MemoryManager. This can be useful for debugging, but will hurt performance in
    /// most cases
    #[clap(long, value_name = "bool")]
    #[clap(about = HELP_MSGS.get("disable_memory_manager").unwrap())]
    disable_memory_manager: Option<bool>,

    /// Disable shim-side syscall handler to force hot-path syscalls to be handled via an inter-process syscall with Shadow
    #[clap(long, value_name = "bool")]
    #[clap(about = HELP_MSGS.get("disable_shim_syscall_handler").unwrap())]
    disable_shim_syscall_handler: Option<bool>,

    /// Use CPU pinning
    #[clap(long, value_name = "bool", next_line_help = true)]
    #[clap(about = HELP_MSGS.get("pin_cpus").unwrap())]
    pin_cpus: Option<bool>,

    /// Which interposition method to use
    #[clap(long, next_line_help = true)]
    #[clap(about = HELP_MSGS.get("interpose_method").unwrap())]
    interpose_method: Option<InterposeMethod>,

    /// If set, overrides the automatically calculated minimum time workers may run ahead when sending events between nodes
    #[clap(long, value_name = "milliseconds")]
    #[clap(about = HELP_MSGS.get("runahead").unwrap())]
    runahead: Option<u32>,

    /// The event scheduler's policy for thread synchronization
    #[clap(long)]
    #[clap(about = HELP_MSGS.get("scheduler_policy").unwrap())]
    scheduler_policy: Option<SchedulerPolicy>,
}

impl ExperimentalOptions {
    /// Replace unset (`None`) values of `base` with values from `default`.
    pub fn merge(base: &Self, default: &Self) -> Self {
        let mut base = base.clone();
        base.merge(default.clone());
        base
    }
}

impl Default for ExperimentalOptions {
    fn default() -> Self {
        Self {
            set_sched_fifo: Some(false),
            disable_o_n_waitpid_workarounds: Some(false),
            disable_explicit_block_message: Some(false),
            enable_syscall_counters: Some(false),
            disable_object_counters: Some(false),
            preload_spin_max: Some(8096),
            max_concurrency: None,
            disable_memory_manager: Some(false),
            disable_shim_syscall_handler: Some(false),
            pin_cpus: Some(false),
            interpose_method: Some(InterposeMethod::Ptrace),
            runahead: Some(0),
            scheduler_policy: Some(SchedulerPolicy::Steal),
        }
    }
}

#[derive(Debug, Clone, Clap, Serialize, Deserialize, Merge, JsonSchema)]
#[clap(help_heading = "(Host Defaults) Default options for hosts")]
#[serde(default)]
pub struct HostDefaultOptions {
    #[clap(long)]
    #[clap(about = HELP_MSGS.get("host_log_level").unwrap())]
    host_log_level: Option<LogLevel>,

    /// Log LEVEL at which to print node statistics
    #[clap(long, value_name = "LEVEL")]
    #[clap(about = HELP_MSGS.get("host_heartbeat_log_level").unwrap())]
    host_heartbeat_log_level: Option<LogLevel>,

    /// List of information to show in heartbeat
    #[clap(long, parse(try_from_str = parse_set_log_info_flags))]
    #[clap(about = HELP_MSGS.get("host_heartbeat_log_info").unwrap())]
    host_heartbeat_log_info: Option<std::collections::HashSet<LogInfoFlag>>,

    #[clap(long, value_name = "seconds")]
    #[clap(about = HELP_MSGS.get("host_heartbeat_interval").unwrap())]
    host_heartbeat_interval: Option<u32>,

    #[clap(long)]
    #[clap(about = HELP_MSGS.get("log_pcap").unwrap())]
    log_pcap: Option<bool>,

    /// Where to save the pcap files (relative to the host directory)
    #[clap(long)]
    #[clap(about = HELP_MSGS.get("pcap_dir").unwrap())]
    pcap_dir: Option<String>,

    #[clap(long)]
    #[clap(about = HELP_MSGS.get("send_buf_size").unwrap())]
    send_buf_size: Option<u64>,

    #[clap(long)]
    #[clap(about = HELP_MSGS.get("send_autotune").unwrap())]
    send_autotune: Option<bool>,

    #[clap(long)]
    #[clap(about = HELP_MSGS.get("recv_buf_size").unwrap())]
    recv_buf_size: Option<u64>,

    #[clap(long)]
    #[clap(about = HELP_MSGS.get("recv_autotune").unwrap())]
    recv_autotune: Option<bool>,

    #[clap(long)]
    #[clap(about = HELP_MSGS.get("interface_buf_size").unwrap())]
    interface_buf_size: Option<u64>,

    #[clap(long)]
    #[clap(about = HELP_MSGS.get("interface_qdisc").unwrap())]
    interface_qdisc: Option<QDiscMode>,

    #[clap(long)]
    #[clap(about = HELP_MSGS.get("ip_hint").unwrap())]
    ip_hint: Option<String>,

    #[clap(long)]
    #[clap(about = HELP_MSGS.get("country_code_hint").unwrap())]
    country_code_hint: Option<String>,

    #[clap(long)]
    #[clap(about = HELP_MSGS.get("city_code_hint").unwrap())]
    city_code_hint: Option<String>,

    #[clap(long)]
    #[clap(about = HELP_MSGS.get("geo_code_hint").unwrap())]
    geo_code_hint: Option<String>,

    #[clap(long)]
    #[clap(about = HELP_MSGS.get("type_hint").unwrap())]
    type_hint: Option<String>,

    #[clap(long)]
    #[clap(about = HELP_MSGS.get("bandwidth_down").unwrap())]
    bandwidth_down: Option<u64>,

    #[clap(long)]
    #[clap(about = HELP_MSGS.get("bandwidth_up").unwrap())]
    bandwidth_up: Option<u64>,
}

impl HostDefaultOptions {
    pub fn new_empty() -> Self {
        Self {
            host_log_level: None,
            host_heartbeat_log_level: None,
            host_heartbeat_log_info: None,
            host_heartbeat_interval: None,
            log_pcap: None,
            pcap_dir: None,
            send_buf_size: None,
            send_autotune: None,
            recv_buf_size: None,
            recv_autotune: None,
            interface_buf_size: None,
            interface_qdisc: None,
            ip_hint: None,
            country_code_hint: None,
            city_code_hint: None,
            geo_code_hint: None,
            type_hint: None,
            bandwidth_down: None,
            bandwidth_up: None,
        }
    }

    /// Replace unset (`None`) values of `base` with values from `default`.
    pub fn merge(base: &Self, default: &Self) -> Self {
        let mut base = base.clone();
        base.merge(default.clone());
        base
    }
}

impl Default for HostDefaultOptions {
    fn default() -> Self {
        Self {
            host_log_level: None,
            host_heartbeat_log_level: Some(LogLevel::Message),
            host_heartbeat_log_info: Some(std::array::IntoIter::new([LogInfoFlag::Node]).collect()),
            host_heartbeat_interval: Some(1),
            log_pcap: Some(false),
            pcap_dir: Some("shadow.pcap".to_string()),
            send_buf_size: Some(131_072),
            send_autotune: Some(true),
            recv_buf_size: Some(174_760),
            recv_autotune: Some(true),
            interface_buf_size: Some(0),
            interface_qdisc: Some(QDiscMode::Fifo),
            ip_hint: None,
            country_code_hint: None,
            city_code_hint: None,
            geo_code_hint: None,
            type_hint: None,
            bandwidth_down: None,
            bandwidth_up: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessOptions {
    path: std::path::PathBuf,

    #[serde(default = "default_args_empty")]
    args: ProcessArgs,

    #[serde(default)]
    quantity: Quantity,

    #[serde(default)]
    start_time: u32,

    #[serde(default)]
    stop_time: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostOptions {
    processes: Vec<ProcessOptions>,

    #[serde(default)]
    quantity: Quantity,

    #[serde(default = "HostDefaultOptions::new_empty")]
    options: HostDefaultOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Critical,
    Warning,
    Message,
    Info,
    Debug,
    Trace,
}

impl std::str::FromStr for LogLevel {
    type Err = serde_yaml::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_yaml::from_str(s)
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
#[repr(C)]
pub enum InterposeMethod {
    /// Attach to child using ptrace and use it to interpose syscalls etc.
    Ptrace,
    /// Use LD_PRELOAD to load a library that implements the libC interface which will
    /// route syscalls to Shadow.
    Preload,
    /// Use both PRELOAD and PTRACE based interposition.
    Hybrid,
}

impl std::str::FromStr for InterposeMethod {
    type Err = serde_yaml::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_yaml::from_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SchedulerPolicy {
    Thread,
    Host,
    Steal,
    ThreadXThread,
    ThreadXHost,
}

impl std::str::FromStr for SchedulerPolicy {
    type Err = serde_yaml::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_yaml::from_str(s)
    }
}

impl std::fmt::Display for SchedulerPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Thread => write!(f, "thread"),
            Self::Host => write!(f, "host"),
            Self::Steal => write!(f, "steal"),
            Self::ThreadXThread => write!(f, "threadXthread"),
            Self::ThreadXHost => write!(f, "threadXhost"),
        }
    }
}

fn default_data_directory() -> Option<String> {
    Some("shadow.data".into())
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, ArgEnum, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum LogInfoFlag {
    Node,
    Socket,
    Ram,
}

impl std::str::FromStr for LogInfoFlag {
    type Err = serde_yaml::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_yaml::from_str(s)
    }
}

/// Parse a string as a set of `LogInfoFlag` values.
fn parse_set_log_info_flags(
    s: &str,
) -> Result<std::collections::HashSet<LogInfoFlag>, serde_yaml::Error> {
    let flags: Result<std::collections::HashSet<LogInfoFlag>, _> =
        s.split(",").map(|x| x.trim().parse()).collect();
    Ok(flags?)
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, ArgEnum, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
#[repr(C)]
pub enum QDiscMode {
    Fifo,
    RoundRobin,
}

impl std::str::FromStr for QDiscMode {
    type Err = serde_yaml::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_yaml::from_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum Topology {
    Path(String),
    GraphMl(String),
    Plain,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Quantity(u32);

impl Default for Quantity {
    fn default() -> Self {
        Self(1)
    }
}

impl std::ops::Deref for Quantity {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ProcessArgs {
    List(Vec<String>),
    Str(String),
}

/// Helper function for serde default `ProcessArgs::Str("")` values.
fn default_args_empty() -> ProcessArgs {
    ProcessArgs::Str("".to_string())
}

/// Helper function for serde default `Some(0)` values.
fn default_some_0() -> Option<u32> {
    Some(0)
}

/// Helper function for serde default `Some(0)` values.
fn default_some_1() -> Option<u32> {
    Some(1)
}

/// Helper function for serde default `Some(LogLevel::Info)` values.
fn default_some_info() -> Option<LogLevel> {
    Some(LogLevel::Info)
}

/// Generate help strings for objects in a JSON schema, including the Serde defaults if available.
fn generate_help_strs(
    schema: schemars::schema::RootSchema,
) -> std::collections::HashMap<String, String> {
    let mut defaults = std::collections::HashMap::<String, String>::new();
    for (name, obj) in &schema.schema.object.as_ref().unwrap().properties {
        let meta = obj.clone().into_object().metadata.unwrap();
        let description = meta.description.or(Some("".to_string())).unwrap();
        match meta.default {
            Some(default) => defaults.insert(
                name.clone(),
                format!("{} [default: {}]", description, default),
            ),
            None => defaults.insert(name.clone(), description.to_string()),
        };
    }
    defaults
}

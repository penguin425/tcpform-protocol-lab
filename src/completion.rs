//! Dependency-free shell completion script generation.

pub fn generate(shell: &str) -> Result<&'static str, String> {
    match shell {
        "bash" => Ok(BASH),
        "zsh" => Ok(ZSH),
        other => Err(format!(
            "unsupported shell `{other}`; supported shells: bash, zsh"
        )),
    }
}

#[cfg(test)]
const COMMANDS: &str = "validate list plan visualize serve fmt migrate init template schema snapshot ci-snapshot ci-report lsp gate bundle replay-bundle anonymize orchestrate proxy explore generate-faults fuzz-export plugin tls-audit differential conformance interop platform run test doctor completion import-pcap import-kaitai packetdrill help";

const BASH: &str = r#"_tcpform() {
  local cur prev commands
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  commands="validate list plan visualize serve fmt migrate init template schema snapshot ci-snapshot ci-report lsp gate bundle replay-bundle anonymize orchestrate proxy explore generate-faults fuzz-export plugin tls-audit differential conformance interop platform run test doctor completion import-pcap import-kaitai packetdrill help"
  case "$prev" in
    completion) COMPREPLY=( $(compgen -W "bash zsh" -- "$cur") ); return ;;
    template) COMPREPLY=( $(compgen -W "list show search add" -- "$cur") ); return ;;
    --template) COMPREPLY=( $(compgen -W "tcp-handshake dns http websocket tls" -- "$cur") ); return ;;
    --output|--config|--markdown|--json|--junit|--pcap|--pcapng|--baseline|--auth-config|--cert|--ca) COMPREPLY=( $(compgen -f -- "$cur") ); return ;;
  esac
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
  elif [[ $cur == -* ]]; then
    COMPREPLY=( $(compgen -W "--json --check --write --output --config --template --force --help" -- "$cur") )
  else
    COMPREPLY=( $(compgen -f -- "$cur") )
  fi
}
complete -F _tcpform tcpform
"#;

const ZSH: &str = r#"#compdef tcpform

_tcpform() {
  local -a commands templates
  commands=(
    'validate:parse and validate protocols' 'list:list protocols' 'plan:show execution plan'
    'visualize:generate visualizer assets' 'serve:start visualizer server' 'fmt:format DSL files'
    'migrate:migrate DSL syntax' 'init:create a project' 'template:list or show templates'
    'schema:print machine-readable schema' 'snapshot:create or check a local snapshot' 'ci-snapshot:create CI snapshot' 'ci-report:compare CI snapshots'
    'lsp:start language server' 'gate:evaluate metrics' 'bundle:create reproduction bundle'
    'replay-bundle:replay a bundle' 'anonymize:anonymize a report' 'orchestrate:run a scenario'
    'proxy:start protocol proxy' 'explore:explore fault matrix' 'generate-faults:generate fault cases'
    'fuzz-export:generate boofuzz harnesses or AFLNet seeds'
    'plugin:invoke a plugin' 'tls-audit:audit TLS' 'differential:compare implementations'
    'conformance:test an implementation for protocol conformance'
    'interop:test interoperability across multiple implementations'
    'platform:platform integrations' 'run:run a protocol' 'test:run case suites'
    'doctor:diagnose project and host' 'completion:generate shell completion' 'help:show help'
    'import-pcap:generate starter DSL from PCAP or PCAPNG'
    'import-kaitai:import a Kaitai Struct ksy schema'
    'packetdrill:import or export packetdrill packet scripts'
  )
  templates=(tcp-handshake dns http websocket tls)
  if (( CURRENT == 2 )); then
    _describe 'command' commands
    return
  fi
  case $words[2] in
    completion) _values 'shell' bash zsh ;;
    template) _values 'template command' list show search add ;;
    fuzz-export) _values 'fuzzer' boofuzz aflnet ;;
    packetdrill) _values 'conversion direction' import export ;;
    init) _arguments '1:directory:_files -/' '--name[project name]:name' '--template[protocol template]:template:($templates)' '--force[overwrite generated files]' ;;
    doctor) _arguments '1:project directory:_files -/' '--json[emit JSON report]' ;;
    *) _arguments '*:file:_files' '--json[emit JSON]' '--output[output path]:path:_files' '--help[show help]' ;;
  esac
}

_tcpform "$@"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts_cover_every_command_and_supported_shell() {
        for command in COMMANDS.split_whitespace() {
            assert!(BASH.contains(command), "bash: {command}");
            assert!(ZSH.contains(command), "zsh: {command}");
        }
        assert!(generate("bash").unwrap().contains("complete -F"));
        assert!(generate("zsh").unwrap().contains("#compdef"));
        assert!(generate("fish").is_err());
    }
}

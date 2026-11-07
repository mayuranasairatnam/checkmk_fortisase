"""
Pass the Checkmk password-store reference to the special agent.
"""
from cmk.server_side_calls.v1 import Secret, SpecialAgentCommand, SpecialAgentConfig, noop_parser


def commands(params, host_config):
    """
    Build the special agent invocation without expanding authentication secrets.

    Input:
        params: Validated Checkmk rule parameters or API query parameters.
        host_config: Checkmk host configuration; the agent uses its built-in portal URL.

    Output:
        Yields a SpecialAgentCommand containing a Secret reference and optional connection arguments.

    """
    secret = params['api_password']
    if not isinstance(secret, Secret):
        raise TypeError('Expected a Checkmk Secret')
    args = ['--api-id', params['api_id'], '--api-password-id', secret]
    if 'timeout' in params:
        args.extend(['--timeout', str(int(params['timeout']))])
    if params.get('tls', 'verify') == 'skip':
        args.append('--no-verify-tls')
    yield SpecialAgentCommand(command_arguments=args)


special_agent_fortisase = SpecialAgentConfig(
    name='fortisase', parameter_parser=noop_parser, commands_function=commands)

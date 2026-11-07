"""
Offline transport and check tests; API doubles do not replace site validation.
"""
import ast
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone
from enum import IntEnum
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
FAMILY = ROOT / 'cmk_addons_plugins/fortisase'
sys.path.insert(0, str(ROOT))


def load(name, path):
    """
    Load a Python module, including extensionless special agents.

    Input:
        Arguments supplied by the test fixtures or the check under test.

    Output:
        Imported module after executing the supplied source file.

    """
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


try:
    import cmk.agent_based.v2 as api
except ImportError:
    class State(IntEnum):
        """
        Offline stand-in for Checkmk monitoring states.

        Input:
            Constructor arguments supported by the test double or test runner.

        Output:
            State instance.

        """
        OK, WARN, CRIT, UNKNOWN = range(4)

    class Record:
        """
        Attribute container used by the offline Checkmk API doubles.

        Input:
            Constructor arguments supported by the test double or test runner.

        Output:
            Record instance.

        """
        def __init__(self, **kwargs):
            """
            Initialize the offline result or metric record.

            Input:
                Arguments supplied by the test fixtures or the check under test.

            Output:
                None; stores the supplied record attributes.

            """
            self.__dict__.update(kwargs)

    class Metric(Record):
        """
        Offline metric record containing a name and value.

        Input:
            Constructor arguments supported by the test double or test runner.

        Output:
            Metric instance.

        """
        def __init__(self, name, value, **kwargs):
            """
            Initialize the offline result or metric record.

            Input:
                Arguments supplied by the test fixtures or the check under test.

            Output:
                None; stores the supplied record attributes.

            """
            super().__init__(name=name, value=value, **kwargs)

    class Result(Record):
        """
        Model the Checkmk result text constraints that caused the production crash.

        Input:
            state: Check state.
            summary, notice: Exactly one non-empty result message.
            details: Optional non-empty detail text.

        Output:
            Result record; invalid or empty supplied text raises ValueError.

        """
        def __init__(self, *, state, summary=None, notice=None, details=None):
            """
            Validate supplied text and apply the default details behavior.

            Input:
                state: Monitoring state for this individual result.
                summary, notice: Mutually exclusive message fields.
                details: Optional replacement for the default message in service details.

            Output:
                None; stores only valid result fields.

            """
            for name, value in (('summary', summary), ('notice', notice), ('details', details)):
                if value is not None and (not isinstance(value, str) or not value):
                    raise ValueError(f'{name} must be non-empty str or None')
            if (summary is None) == (notice is None):
                raise ValueError('Specify exactly one of summary and notice')
            message = summary or notice
            shown = message if summary is not None or state != State.OK else ''
            super().__init__(state=state, summary=shown, notice=notice, details=details or message)

    def check_levels(value, levels_lower=None, metric_name=None, levels_upper=None, **kwargs):
        """
        Apply lower warning and critical levels in the offline Checkmk double.

        Input:
            Arguments supplied by the test fixtures or the check under test.

        Output:
            Yields monitoring results and an optional metric.

        """
        state = State.OK
        if levels_lower and levels_lower[0] == 'fixed':
            warn, crit = levels_lower[1]
            state = State.CRIT if value < crit else State.WARN if value < warn else State.OK
        if levels_upper and levels_upper[0] == 'fixed':
            warn, crit = levels_upper[1]
            state = State.CRIT if value >= crit else State.WARN if value >= warn else state
        yield Result(state=state, summary=str(value))
        if metric_name:
            yield Metric(metric_name, value)

    api = types.ModuleType('cmk.agent_based.v2')
    for name in ('AgentSection', 'CheckPlugin', 'Service'):
        setattr(api, name, Record)
    for name in ('CheckResult', 'DiscoveryResult', 'StringTable'):
        setattr(api, name, list)
    api.State, api.Metric, api.Result, api.check_levels = State, Metric, Result, check_levels
    api.render = types.SimpleNamespace(bytes=str, networkbandwidth=str)
    for name in ('cmk', 'cmk.agent_based'):
        sys.modules[name] = types.ModuleType(name)
    sys.modules['cmk.agent_based.v2'] = api

from cmk_addons.plugins.fortisase.agent_based import (  # noqa: E402 - Install Checkmk API doubles first.
    fortisase_api as status, fortisase_certificates as certs,
    fortisase_license as license_check, fortisase_private_access as private_access, fortisase_idp as idp,
    fortisase_swg as swg, fortisase_vpn as vpn,
    fortisase_bandwidth as traffic, fortisase_pop as pop,
)
from cmk_addons.plugins.fortisase.lib.common import (  # noqa: E402 - Install Checkmk API doubles first.
    number, parse_json, parse_traffic, parse_sessions, parse_certificates, expiry_timestamp, parse_license,
)
from cmk_addons.plugins.fortisase.lib import common as sessions  # noqa: E402 - Install Checkmk API doubles first.


def parsed(parser, value):
    """
    Pass a fixture through the same JSON boundary as the Checkmk agent.

    Input:
        parser: Registered section parser.
        value: JSON-serializable API fixture.

    Output:
        Normalized typed section used by discovery and checking.

    """
    return parser([[json.dumps(value)]])
agent = load('sase_agent', FAMILY / 'libexec/agent_fortisase')


def response(data, code=200):
    """
    Construct a mocked JSON HTTP response.

    Input:
        Arguments supplied by the test fixtures or the check under test.

    Output:
        Response object exposing status_code and json().

    """
    return types.SimpleNamespace(status_code=code, json=lambda: data)


def metrics(results):
    """
    Extract named metric values from check results.

    Input:
        Arguments supplied by the test fixtures or the check under test.

    Output:
        Dictionary mapping emitted metric names to their numeric values.

    """
    return {result.name: result.value for result in results if isinstance(result, api.Metric)}


class TransportTests(unittest.TestCase):
    """
    Transport, authentication and secure credential lifecycle tests.

    Input:
        Constructor arguments supported by the test double or test runner.

    Output:
        TransportTests instance.

    """
    def setUp(self):
        """
        Prepare an isolated token cache and mocked HTTP session.

        Input:
            Arguments supplied by the test fixtures or the check under test.

        Output:
            None; registers cleanup and prepares the API client.

        """
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.cache = patch.object(agent, '_cache_dir', return_value=Path(self.directory.name))
        self.cache.start()
        self.addCleanup(self.cache.stop)
        self.client = agent.FortiSASEClient(agent.parse_arguments([
            '--api-id', 'test-account', '--password-from-stdin']), 'test-password')
        self.client.session = Mock()
        self.client.session.post.return_value = response({
            'access_token': 'test-token', 'refresh_token': 'test-refresh', 'expires_in': 3600})

    def test_password_grant_and_cache_reuse(self):
        """
        Verify password grant and cache reuse.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        self.client.authenticate()
        self.assertEqual(self.client.session.post.call_args.kwargs['json']['grant_type'], 'password')
        self.assertTrue(self.client.session.post.call_args.kwargs['verify'])
        self.assertFalse(self.client.session.post.call_args.kwargs['allow_redirects'])
        self.assertEqual(self.client._cache_file.stat().st_mode & 0o777, 0o600)
        self.client.authenticate()
        self.assertEqual(self.client.session.post.call_count, 1)

    def test_expiry_refresh_preserves_refresh_token(self):
        """
        Verify expiry refresh preserves refresh token.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        self.client._write_cache('old', 'old-refresh', 1)
        self.client.session.post.return_value = response({'access_token': 'renewed', 'expires_in': 7200})
        self.client.authenticate()
        self.assertEqual(self.client.session.post.call_args.kwargs['json']['refresh_token'], 'old-refresh')
        self.assertEqual(self.client._read_cache()['refresh_token'], 'old-refresh')

    def test_refresh_failure_falls_back_without_leaking_response(self):
        """
        Verify refresh failure falls back without leaking response.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        self.client._write_cache('old', 'old-refresh', 1)
        self.client.session.post.side_effect = [response({'secret': 'private'}, 400),
            response({'access_token': 'new'})]
        self.client.authenticate()
        self.assertEqual(self.client.session.post.call_count, 2)
        self.assertEqual(self.client._token, 'new')

    def test_401_retries_once_and_memoizes(self):
        """
        Verify 401 retries once and memoizes.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        self.client.session.get.side_effect = [response({}, 401), response({'data': []})]
        data = self.client.get('/monitor-api/v1/traffic-history', {'type': 'FortiGate'})
        self.assertEqual(data, {'data': []})
        self.client.get('/monitor-api/v1/traffic-history', {'type': 'FortiGate'})
        self.assertEqual(self.client.session.get.call_count, 2)
        self.assertEqual(self.client.session.post.call_count, 1)
        self.assertEqual(self.client.session.get.call_args.kwargs['headers']['Authorization'], 'Bearer test-token')

    def test_second_401_is_an_error(self):
        """
        Verify second 401 is an error.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        self.client.session.get.return_value = response({}, 401)
        with self.assertRaisesRegex(agent.APIError, 'HTTP 401'):
            self.client.get('/monitor-api/v1/user/vpn/sessions')
        self.assertEqual(self.client.session.get.call_count, 2)

    def test_rejects_application_errors_invalid_json_and_shapes(self):
        """
        Verify rejects application errors invalid json and shapes.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        invalid = Mock(status_code=200)
        invalid.json.side_effect = ValueError('secret response')
        for result in (response({'code': 403, 'data': []}), response({'data': 'bad'}), invalid):
            with self.subTest(result=result):
                self.client.session.get.return_value = result
                with self.assertRaises(agent.APIError) as error:
                    self.client.get('/monitor-api/v1/user/vpn/sessions')
                self.assertNotIn('secret', str(error.exception))

    def test_invalid_cache_and_nonfinite_expiry(self):
        """
        Verify invalid cache and nonfinite expiry.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        for value in ('[]', '{}', '{broken', '{"expires_at":"bad"}', '{"expires_at":NaN}'):
            self.client._cache_file.write_text(value)
            self.client.authenticate()
            self.assertEqual(self.client._token, 'test-token')

    def test_cache_identity_distinguishes_accounts_origins_and_passwords(self):
        """
        Verify cache identity distinguishes accounts origins and passwords.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        other = agent.FortiSASEClient(agent.parse_arguments([
            '--api-id', 'test-account', '--password-from-stdin']), 'rotated-password')
        self.assertNotEqual(self.client._cache_file, other._cache_file)

    def test_debug_does_not_print_oauth_secrets(self):
        """
        Verify debug does not print oauth secrets.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        self.client.debug = True
        stream = io.StringIO()
        with redirect_stderr(stream):
            self.client.authenticate()
        for secret in ('test-token', 'test-refresh', 'test-password'):
            self.assertNotIn(secret, stream.getvalue())

    def test_collect_deduplicates_and_keeps_partial_results(self):
        """
        Verify collect deduplicates and keeps partial results.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        def get(endpoint, params):
            """
            Simulate one failed endpoint while keeping other responses available.

            Input:
                Arguments supplied by the test fixtures or the check under test.

            Output:
                JSON response, or APIError for the deliberately failed traffic type.

            """
            if params == {'type': 'FortiGate'}:
                raise agent.APIError('API request failed (HTTP 403)')
            if endpoint == agent.REGIONS_ENDPOINT:
                return {'data': {'sites': {'federated_sites': []}}}
            if endpoint == agent.IDP_ENDPOINT:
                return {'result': {'retval': 1}, 'data': []}
            if endpoint == agent.CONNECTIONS_ENDPOINT:
                return {'hubs': []}
            if endpoint == agent.SEATS_ENDPOINT:
                return {'result': {'retval': 1}, 'data': {'seats': 50, 'used': 1}}
            return {'data': []}
        client = Mock()
        client.get.side_effect = get
        output = io.StringIO()
        with redirect_stdout(output):
            agent.collect(client)
        self.assertEqual(client.get.call_count, 14)
        lines = output.getvalue().splitlines()
        report = json.loads(lines[-1])
        self.assertEqual(report['successful'], 13)
        self.assertEqual(len(report['errors']), 1)
        self.assertIn('<<<fortisase_vpn_sessions:sep(0)>>>', lines)
        self.assertNotIn('<<<fortisase_bps_fortigate:sep(0)>>>', lines)
        self.assertEqual(list(status.check_api(report))[0].state, api.State.WARN)

    def test_authentication_failure_emits_critical_api_service(self):
        """
        Verify authentication failure emits critical api service.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        client = Mock()
        client.authenticate.side_effect = agent.APIError('OAuth authentication failed (HTTP 401)')
        stream = io.StringIO()
        with redirect_stdout(stream):
            agent.collect(client)
        report = json.loads(stream.getvalue().splitlines()[-1])
        self.assertEqual(list(status.check_api(report))[0].state, api.State.CRIT)
        client.get.assert_not_called()

    def test_cli_rejects_http_and_ambiguous_secrets(self):
        """
        Verify cli rejects http and ambiguous secrets.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        for options in (['--base-url', 'http://portal.example'], ['--api-password-id', 'ref'], ['--timeout', '0']):
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                agent.parse_arguments(['--api-id', 'test', '--password-from-stdin'] + options)

    def test_main_resolves_store_reference_and_closes_session(self):
        """
        Verify main resolves store reference and closes session.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        client = Mock()
        with patch.object(agent, 'password_from_reference', return_value='resolved') as lookup, \
                patch.object(agent, 'FortiSASEClient', return_value=client), \
                patch.object(agent, 'collect') as collect:
            from contextlib import nullcontext
            client.locked.return_value = nullcontext()
            self.assertEqual(agent.main(['--api-id', 'test', '--api-password-id', 'id:/store']), 0)
        lookup.assert_called_once_with('id:/store')
        collect.assert_called_once_with(client)
        client.session.close.assert_called_once()

    def test_secret_is_forwarded_without_expansion(self):
        """
        Verify secret is forwarded without expansion.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        class Secret:
            """
            Secret double that rejects accidental string expansion.

            Input:
                Constructor arguments supported by the test double or test runner.

            Output:
                Secret instance.

            """
            def __str__(self):
                """
                Reject accidental expansion of the secret into process arguments.

                Input:
                    Arguments supplied by the test fixtures or the check under test.

                Output:
                    Raises AssertionError if the secret is converted to a string.

                """
                raise AssertionError('Secret must not be expanded')
        module = types.ModuleType('cmk.server_side_calls.v1')
        module.Secret = Secret
        module.SpecialAgentCommand = module.SpecialAgentConfig = lambda **kw: types.SimpleNamespace(**kw)
        module.noop_parser = lambda v: v
        with patch.dict(sys.modules, {'cmk.server_side_calls.v1': module}):
            calls = load('sase_calls', FAMILY / 'server_side_calls/fortisase.py')
        secret = Secret()
        command, = calls.commands({'api_id': 'test', 'api_password': secret,
            'base_url': 'https://retired.example', 'cache_ttl': 999, 'timeout': 45}, None)
        args = command.command_arguments
        self.assertIs(args[args.index('--api-password-id') + 1], secret)
        self.assertNotIn('--base-url', args)
        self.assertNotIn('--cache-ttl', args)
        self.assertEqual(args[args.index('--timeout') + 1], '45')
        with self.assertRaises(TypeError):
            list(calls.commands({'api_id': 'test', 'api_password': 'plaintext'}, None))







    def test_saved_rule_migration_removes_only_retired_settings(self):
        """
        Verify migration preserves credentials and supported settings without mutating saved data.

        Input:
            Legacy integration parameters containing portal and OAuth lifetime overrides.

        Output:
            Migrated parameters retain the secret object, timeout and TLS selection only.

        """
        source = (FAMILY / 'rulesets/special_agent.py').read_text()
        tree = ast.parse(source)
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == 'migrate_connection_settings')
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<rule migration>', 'exec'), namespace)
        migrate = namespace['migrate_connection_settings']
        secret = object()
        legacy = {'api_id': 'account', 'api_password': secret, 'timeout': 45,
                  'tls': 'skip', 'base_url': 'https://retired.example', 'cache_ttl': 999}
        snapshot = dict(legacy)
        expected = {key: value for key, value in legacy.items() if key not in ('base_url', 'cache_ttl')}
        self.assertEqual(migrate(legacy), expected)
        self.assertEqual(legacy, snapshot)
        self.assertIs(migrate(legacy)['api_password'], secret)
        self.assertEqual(migrate(expected), expected)
        self.assertIsNone(migrate(None))


class CheckTests(unittest.TestCase):
    """
    Discovery, metrics and monitoring state tests.

    Input:
        Constructor arguments supported by the test double or test runner.

    Output:
        CheckTests instance.

    """
    def test_successful_api_check_never_supplies_empty_detail_text(self):
        """
        Reproduce the production success case with strict Checkmk text validation.

        Input:
            Successful collection status with an empty error list.

        Output:
            An OK result and duration metric without a ValueError from empty details.

        """
        results = list(status.check_api({'errors': [], 'successful': 9, 'total': 9, 'duration': 1.5}))
        self.assertEqual(results[0].state, api.State.OK)
        self.assertEqual(results[0].summary, 'All 9 API requests successful')
        self.assertTrue(results[0].details)
        self.assertEqual(metrics(results)['fortisase_api_duration'], 1.5)

    def test_pop_bandwidth_is_discovered_once_and_not_duplicated_in_sessions(self):
        """
        Verify shared regional bandwidth is owned by the PoP service.

        Input:
            Two traffic sources at one location and empty protocol session inventories.

        Output:
            One PoP service with all rates; session services expose only their own measurements.

        """
        section = parsed(parse_sessions, {'data': [
            {'region': 'eu', 'regionLabel': 'Zurich', 'data': []}]})
        user = parsed(parse_traffic, {'data': [
            {'name': 'Receive:Zurich:InboundUser', 'data': [{'bps': 8000}]},
            {'name': 'Transmit:Zurich:InboundUser', 'data': [{'bps': 0}]}]})
        outbound = parsed(parse_traffic, {'data': [
            {'name': 'Receive:Zurich:Outbound', 'data': [{'bps': 16000}]},
            {'name': 'Transmit:Zurich:Outbound', 'data': [{'bps': 24000}]}]})
        kwargs = {'section_fortisase_bps_inbounduser': user, 'section_fortisase_bps_outbound': outbound}
        plugin = pop.check_plugin_fortisase_pop
        self.assertEqual([service.item for service in plugin.discovery_function(**kwargs)], ['Zurich'])
        self.assertEqual(plugin.service_name, 'FortiSASE VPN/SWG Bandwidth %s')
        results = list(plugin.check_function(item='Zurich', **kwargs))
        self.assertEqual(metrics(results), {'fortisase_inbounduser_bps_rx': 8000,
            'fortisase_inbounduser_bps_tx': 0, 'fortisase_outbound_bps_rx': 16000,
            'fortisase_outbound_bps_tx': 24000})
        self.assertEqual({result.state for result in results if hasattr(result, 'state')}, {api.State.OK})
        for module, kind in ((swg, 'swg'), (vpn, 'vpn')):
            check = getattr(module, f'check_plugin_{kind}_sessions')
            self.assertEqual(check.sections, [f'fortisase_{kind}_sessions'])
            values = metrics(list(check.check_function(item='eu', section=section)))
            self.assertEqual(set(values), {'fortisase_sessions', 'fortisase_received_total', 'fortisase_sent_total'})

    def test_pop_keeps_available_rates_when_one_source_is_missing(self):
        """
        Verify a failed traffic source cannot hide valid PoP data from another source.

        Input:
            Outbound traffic for a location with no user-access response.

        Output:
            A discovered service reporting UNKNOWN and the valid outbound measurement.

        """
        outbound = parsed(parse_traffic, {'data': [
            {'name': 'Receive:Doha:Outbound', 'data': [{'bps': 80}]}]})
        self.assertEqual([service.item for service in pop.discover_pop(None, outbound)], ['Doha'])
        results = list(pop.check_pop('Doha', None, outbound))
        self.assertEqual(metrics(results), {'fortisase_outbound_bps_rx': 80})
        self.assertIn(api.State.UNKNOWN, [result.state for result in results if hasattr(result, 'state')])
        self.assertEqual(list(pop.discover_pop(None, None)), [])

    def test_pop_generic_samples_and_distinct_locations(self):
        """
        Verify non-directional rates and the union of traffic-source locations.

        Input:
            Generic user-access traffic in Zurich and outbound traffic in Doha.

        Output:
            Two separate PoP services and a valid unclassified-rate metric.

        """
        user = parsed(parse_traffic, {'data': [{'name': 'Zurich', 'data': [{'bps': 0}]}]})
        outbound = parsed(parse_traffic, {'data': [{'name': 'Doha', 'data': [{'bps': 80}]}]})
        self.assertEqual([service.item for service in pop.discover_pop(user, outbound)], ['Doha', 'Zurich'])
        results = list(pop.check_pop('Zurich', user, outbound))
        self.assertEqual(metrics(results), {'fortisase_inbounduser_bps': 0})


    def test_bandwidth_names_include_city_and_reported_datacenter(self):
        """
        Verify shared and private-access service names use the requested PoP identity.

        Input:
            Doha and Zurich traffic plus matching VPN/SWG region-label mappings.

        Output:
            One bandwidth service per city/datacenter with correctly resolved original rates.

        """
        inventory = parsed(parse_sessions, {'data': [
            {'region': 'doh-g2', 'regionLabel': 'Doha (Qatar) (G)', 'data': []},
            {'region': 'zrh-g2', 'regionLabel': 'Zurich (Switzerland) (G)', 'data': []}]})
        rates = parsed(parse_traffic, {'data': [
            {'name': 'Receive:Doha (Qatar) (G):InboundUser', 'data': [{'bps': 80}]},
            {'name': 'Receive:Zurich (Switzerland) (G):InboundUser', 'data': [{'bps': 160}]}]})
        shared = pop.check_plugin_fortisase_pop
        kwargs = {'section_fortisase_bps_inbounduser': rates, 'section_fortisase_bps_outbound': rates,
                  'section_fortisase_swg_sessions': inventory, 'section_fortisase_vpn_sessions': inventory}
        items = [service.item for service in shared.discovery_function(**kwargs)]
        self.assertEqual(items, ['Doha (doh-g2)', 'Zurich (zrh-g2)'])
        self.assertEqual(shared.service_name % items[0], 'FortiSASE VPN/SWG Bandwidth Doha (doh-g2)')
        self.assertEqual(metrics(list(shared.check_function(item=items[0], **kwargs)))['fortisase_inbounduser_bps_rx'], 80)
        private = traffic.check_plugin_bps_privateaccess
        private_kwargs = {'section_fortisase_bps_privateaccess': rates,
                          'section_fortisase_swg_sessions': inventory, 'section_fortisase_vpn_sessions': inventory}
        self.assertEqual([service.item for service in private.discovery_function(**private_kwargs)], items)
        self.assertEqual(private.service_name % items[1], 'FortiSASE Private Access Bandwidth Zurich (zrh-g2)')
        self.assertEqual(metrics(list(private.check_function(item=items[1], **private_kwargs)))['fortisase_bps_rx'], 160)

    def test_bandwidth_names_do_not_invent_or_duplicate_datacenter_ids(self):
        """
        Verify missing metadata and multiple region IDs cannot invent split traffic measurements.

        Input:
            One traffic location with absent or multiple matching session datacenters.

        Output:
            Original labels survive absent metadata; shared locations remain single services.

        """
        rates = parsed(parse_traffic, {'data': [
            {'name': 'Receive:Doha (Qatar) (G):InboundUser', 'data': [{'bps': 0}]}]})
        self.assertEqual([service.item for service in pop.discover_pop(rates, rates)], ['Doha (Qatar) (G)'])
        inventory = parsed(parse_sessions, {'data': [
            {'region': 'doh-g1', 'regionLabel': 'Doha (Qatar) (G)', 'data': []},
            {'region': 'doh-g2', 'regionLabel': 'Doha (Qatar) (G)', 'data': []}]})
        self.assertEqual([service.item for service in pop.discover_pop(rates, rates, inventory, inventory)],
                         ['Doha (doh-g1, doh-g2)'])
        results = list(pop.check_pop('Doha (doh-g2)', rates, rates))
        self.assertEqual(results[0].state, api.State.UNKNOWN)




    def test_session_names_include_city_before_datacenter_for_both_protocols(self):
        """
        Verify VPN and SWG names match the bandwidth city/datacenter convention.

        Input:
            Doha and Zurich session inventories containing both labels and region keys.

        Output:
            Human-readable discovered names resolve to their original session measurements.

        """
        section = parsed(parse_sessions, {'data': [
            {'region': 'doh-g2', 'regionLabel': 'Doha (Qatar) (G)', 'data': []},
            {'region': 'zrh-g2', 'regionLabel': 'Zurich (Switzerland) (G)',
             'data': [{'receivedBytes': 10, 'sentBytes': 20}]}]})
        for module, kind in ((vpn, 'vpn'), (swg, 'swg')):
            plugin = getattr(module, f'check_plugin_{kind}_sessions')
            items = [service.item for service in plugin.discovery_function(section=section)]
            self.assertEqual(items, ['Doha (doh-g2)', 'Zurich (zrh-g2)'])
            label = 'SWG' if kind == 'swg' else 'VPN'
            self.assertEqual(plugin.service_name % items[1], f'FortiSASE {label} Zurich (zrh-g2)')
            self.assertEqual(metrics(list(plugin.check_function(item=items[1], section=section)))['fortisase_sessions'], 1)
            self.assertEqual(metrics(list(plugin.check_function(item=items[0], section=section)))['fortisase_sessions'], 0)
            # Existing accepted services continue to work until the discovery rename is reviewed.
            self.assertEqual(metrics(list(plugin.check_function(item='zrh-g2', section=section)))['fortisase_sessions'], 1)

    def test_numeric_values_and_malformed_json(self):
        """
        Verify numeric values and malformed json.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        for value in ('NaN', 'inf', -1, True, None, 'invalid'):
            self.assertIsNone(number(value))
        self.assertEqual(number(0), 0)
        for table in ([], [[]], [['broken']], [['null']]):
            self.assertEqual(parse_json(table), {})

    def test_traffic_rates_aggregate_by_region(self):
        """
        Verify traffic rates aggregate by direction while retaining zero values.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        data = {'data': {'datasets': [
            {'name': 'Receive:Zurich:PrivateAccess', 'data': [{'bps': 8000, 'lastRx': 100, 'rx': 100}]},
            {'name': 'Transmit:Zurich:PrivateAccess', 'data': [{'bps': 0, 'txBytes': 200}]},
            {'name': 'Receive:Zurich:PrivateAccess', 'data': [{'bps': 0}]},
        ]}}
        data = parsed(parse_traffic, data)
        self.assertEqual([s.item for s in traffic.discover_bps(data)], ['Zurich'])
        self.assertEqual(metrics(list(traffic.check_bps('Zurich', data))),
                         {'fortisase_bps_rx': 8000, 'fortisase_bps_tx': 0})

    def test_empty_sessions_are_zero_but_missing_list_is_unknown(self):
        """
        Verify empty sessions are zero but missing list is unknown.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        data = {'data': [{'region': 'eu', 'regionLabel': 'Zurich', 'data': []}]}
        result = list(sessions.check_sessions('eu', parsed(parse_sessions, data)))
        self.assertEqual(metrics(result)['fortisase_sessions'], 0)
        self.assertEqual(result[0].state, api.State.OK)
        data['data'][0].pop('data')
        self.assertEqual(list(sessions.check_sessions('eu', parsed(parse_sessions, data)))[0].state, api.State.UNKNOWN)

    def test_sessions_report_only_protocol_counters(self):
        """
        Verify protocol services retain session measurements without shared bandwidth.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        data = {'data': [{'region': 'eu', 'regionLabel': 'Zurich', 'data': [
            {'receivedBytes': 10, 'sentBytes': 20}, {'receivedBytes': 0, 'sentBytes': 5}]}]}
        values = metrics(list(sessions.check_sessions('eu', parsed(parse_sessions, data))))
        self.assertEqual(values['fortisase_sessions'], 2)
        self.assertEqual(values['fortisase_received_total'], 10)
        self.assertEqual(values['fortisase_sent_total'], 25)
        self.assertFalse(any('_bps' in name for name in values))

    def test_certificate_service_names_and_legacy_items(self):
        """
        Verify certificate naming and continued evaluation of previously discovered items.

        Input:
            FortiSASE and custom certificate names with different subject CNs.

        Output:
            Requested service names and identical lifetime metrics for legacy items.

        """
        cn = 'Microsoft Azure Federated SSO Certificate'
        section = parsed(parse_certificates, {'data': [
            {'primaryKey': 'sso', '$meta': {'info': {
                'name': 'FortiSASE', 'subject': {'CN': cn},
                'validTo': '2030-01-01T00:00:00Z'}}},
            {'primaryKey': 'custom', '$meta': {'info': {
                'name': 'Custom', 'subject': {'CN': 'Custom CA'},
                'validTo': '2030-01-01T00:00:00Z'}}}]})
        plugin = certs.check_plugin_remote_certificate
        items = [service.item for service in plugin.discovery_function(section)]
        self.assertEqual([plugin.service_name % item for item in items], [
            f'FortiSASE Certificate ({cn})', 'FortiSASE Certificate Custom (Custom CA)'])
        with patch.object(certs.time, 'time', return_value=1767225600):
            current = list(plugin.check_function(f'({cn})', {}, section))
            legacy = list(plugin.check_function(f'FortiSASE ({cn})', {}, section))
        self.assertEqual(metrics(current), metrics(legacy))
        self.assertIn('fortisase_cert_days_remaining', metrics(current))
        self.assertFalse(any(result.state == api.State.UNKNOWN for result in legacy if isinstance(result, api.Result)))

    def test_certificate_expiry_levels_and_utc(self):
        """
        Verify certificate expiry levels and utc.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        now = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
        entry = {'primaryKey': 'cert', '$meta': {'info': {'validTo': '2026-01-11T00:00:00Z'}}}
        with patch.object(certs.time, 'time', return_value=now):
            values = list(certs.check_certs('cert', {}, parsed(parse_certificates, {'data': [entry]})))
            self.assertEqual(metrics(values)['fortisase_cert_days_remaining'], 10)
            self.assertEqual(values[0].state, api.State.CRIT)
            entry['$meta']['info']['validTo'] = '2026-01-11T00:00:00'
            self.assertEqual((expiry_timestamp(entry['$meta']['info']['validTo']) - now) / 86400, 10)
        entry['$meta']['info']['validTo'] = 'bad'
        self.assertEqual(list(certs.check_certs('cert', {}, parsed(parse_certificates, {'data': [entry]})))[0].state, api.State.UNKNOWN)

    def test_missing_session_counter_keeps_count_and_other_direction(self):
        """
        Verify missing bytes are unavailable rather than silently reported as zero.

        Input:
            A region containing a session with only a sent byte counter.

        Output:
            UNKNOWN for incomplete data, with count and sent bytes still available.

        """
        section = parsed(parse_sessions, {'data': [{'region': 'eu', 'data': [{'sentBytes': 7}]}]})
        results = list(sessions.check_sessions('eu', section))
        values = metrics(results)
        self.assertEqual(values['fortisase_sessions'], 1)
        self.assertEqual(values['fortisase_sent_total'], 7)
        self.assertNotIn('fortisase_received_total', values)
        self.assertIn(api.State.UNKNOWN, [r.state for r in results if hasattr(r, 'state')])

    def test_duplicate_regions_and_certificates_report_ambiguity(self):
        """
        Verify duplicate API identities do not silently overwrite discovered items.

        Input:
            Repeated session region and certificate identifiers.

        Output:
            One discovered item with an UNKNOWN check result for ambiguity.

        """
        region = {'region': 'eu', 'data': []}
        section = parsed(parse_sessions, {'data': [region, region]})
        self.assertEqual(len(list(sessions.discover_sessions(section))), 1)
        self.assertEqual(list(sessions.check_sessions('eu', section))[0].state, api.State.UNKNOWN)
        certificate = {'primaryKey': 'cert', '$meta': {'info': {'validTo': '2030-01-01T00:00:00Z'}}}
        section = parsed(parse_certificates, {'data': [certificate, certificate]})
        self.assertEqual(len(list(certs.discover_certs(section))), 1)
        self.assertEqual(list(certs.check_certs('cert', {}, section))[0].state, api.State.UNKNOWN)

    def test_anonymous_records_do_not_create_placeholder_services(self):
        """
        Verify missing identities remain validation errors rather than unstable service names.

        Input:
            Session, traffic and certificate records without identifiers.

        Output:
            No anonymous discovered services; each section retains validation errors.

        """
        cases = ((parse_sessions, {'data': [{'data': []}]}, sessions.discover_sessions),
                 (parse_traffic, {'data': [{'data': [{'bps': 1}]}]}, traffic.discover_bps),
                 (parse_certificates, {'data': [{}]}, certs.discover_certs))
        for parser, payload, discover in cases:
            with self.subTest(parser=parser.__name__):
                section = parsed(parser, payload)
                self.assertTrue(section.errors)
                self.assertEqual(list(discover(section)), [])

    def test_empty_and_invalid_envelopes_are_distinct(self):
        """
        Verify an empty successful collection remains distinct from malformed JSON or API errors.

        Input:
            Empty API lists, malformed JSON and application error envelopes.

        Output:
            Empty valid sections have no errors; invalid sections retain diagnostics.

        """
        for parser in (parse_sessions, parse_traffic, parse_certificates):
            with self.subTest(parser=parser.__name__):
                self.assertFalse(parsed(parser, {'data': []}).errors)
                self.assertTrue(parser([['broken']]).errors)
                self.assertTrue(parsed(parser, {'code': 403, 'data': []}).errors)

    def test_invalid_final_sample_never_reuses_older_traffic(self):
        """
        Verify malformed final points cannot produce stale throughput metrics.

        Input:
            A valid historical sample followed by a malformed latest sample.

        Output:
            UNKNOWN regional service without a stale receive metric.

        """
        section = parsed(parse_traffic, {'data': [
            {'name': 'Receive:Zurich:FortiGate', 'data': [{'bps': 80}, None]}]})
        results = list(traffic.check_bps('Zurich', section))
        self.assertEqual(results[0].state, api.State.UNKNOWN)
        self.assertNotIn('fortisase_bps_rx', metrics(results))

    def test_overflow_does_not_emit_infinite_metrics(self):
        """
        Verify individually finite samples cannot overflow into exported infinite aggregates.

        Input:
            Two datasets and sessions with values near the floating-point limit.

        Output:
            UNKNOWN status and suppressed overflowing metrics.

        """
        dataset = {'name': 'Receive:Zurich:FortiGate', 'data': [{'bps': 1e308, 'rx': 1e308}]}
        section = parsed(parse_traffic, {'data': [dataset, dataset]})
        self.assertNotIn('fortisase_bps_rx', metrics(list(traffic.check_bps('Zurich', section))))
        region = {'region': 'eu', 'data': [{'receivedBytes': 1e308, 'sentBytes': 0}] * 2}
        section = parsed(parse_sessions, {'data': [region]})
        values = metrics(list(sessions.check_sessions('eu', section)))
        self.assertNotIn('fortisase_received_total', values)
        self.assertEqual(values['fortisase_sessions'], 2)
        self.assertEqual(values['fortisase_sent_total'], 0)

    def test_certificate_lifetime_is_evaluated_at_check_time(self):
        """
        Verify reused parsed certificate data does not freeze remaining lifetime.

        Input:
            One parsed certificate checked twice a day apart.

        Output:
            The second check reports one fewer remaining day.

        """
        section = parsed(parse_certificates, {'data': [
            {'primaryKey': 'cert', '$meta': {'info': {'validTo': '2030-01-01T00:00:00Z'}}}]})
        remaining = []
        for now in (1_800_000_000, 1_800_086_400):
            with patch.object(certs.time, 'time', return_value=now):
                remaining.append(metrics(list(certs.check_certs('cert', {}, section)))['fortisase_cert_days_remaining'])
        self.assertAlmostEqual(remaining[0] - remaining[1], 1)


    def test_graph_catalog_resolves_metric_series_with_consistent_units(self):
        """
        Verify every exported chart references declared metrics of one unit family.

        Input:
            The graphing module loaded against small public-API record doubles.

        Output:
            Unique metric/graph identifiers and complete, unit-consistent chart series.

        """
        modules = {name: types.ModuleType(name) for name in (
            'cmk.graphing.v1', 'cmk.graphing.v1.graphs', 'cmk.graphing.v1.metrics')}
        modules['cmk.graphing.v1'].Title = str
        class Declaration:
            """
            Store graphing constructor arguments for offline catalog validation.

            Input:
                args: Positional notation or unit arguments.
                kwargs: Named declaration attributes.

            Output:
                Record exposing the supplied graphing properties.

            """
            def __init__(self, *args, **kwargs):
                """
                Retain public graphing API arguments without applying rendering behavior.

                Input:
                    args: Positional constructor data.
                    kwargs: Declaration properties inspected by this test.

                Output:
                    None; stores constructor arguments on the record.

                """
                self.args = args
                self.__dict__.update(kwargs)
        graphs_api = modules['cmk.graphing.v1.graphs']
        graphs_api.Graph = graphs_api.MinimalRange = Declaration
        metrics_api = modules['cmk.graphing.v1.metrics']
        for name in ('Metric', 'Unit', 'DecimalNotation', 'IECNotation'):
            setattr(metrics_api, name, Declaration)
        metrics_api.Color = types.SimpleNamespace(**{name: name for name in (
            'BLUE', 'GREEN', 'ORANGE', 'PURPLE', 'YELLOW', 'LIGHT_GREEN', 'LIGHT_BLUE')})
        with patch.dict(sys.modules, modules):
            catalog = load('sase_graph_catalog', FAMILY / 'graphing/fortisase.py')
        measurements = [value for name, value in vars(catalog).items() if name.startswith('metric_')]
        charts = [value for name, value in vars(catalog).items() if name.startswith('graph_')]
        by_name = {metric.name: metric for metric in measurements}
        self.assertEqual(len(measurements), len(by_name))
        self.assertEqual(len(charts), len({chart.name for chart in charts}))
        self.assertIn('fortisase_api_duration', by_name)
        for chart in charts:
            self.assertTrue(chart.simple_lines)
            for metric in chart.simple_lines:
                self.assertIn(metric, by_name)
            self.assertEqual(len({id(by_name[name].unit) for name in chart.simple_lines}), 1)

    def test_separate_session_plugins_bind_their_own_inventory(self):
        """
        Exercise each session registration through Checkmk-style named section binding.

        Input:
            Distinct SWG and VPN inventories with optional traffic sections absent.

        Output:
            Each plugin discovers and checks its own region with the expected session count.

        """
        for module, kind, count in ((swg, 'swg', 1), (vpn, 'vpn', 2)):
            with self.subTest(kind=kind):
                section = parsed(parse_sessions, {'data': [{'region': kind, 'data': [
                    {'receivedBytes': 1, 'sentBytes': 2}] * count}]})
                plugin = getattr(module, f'check_plugin_{kind}_sessions')
                kwargs = {'section': section}
                self.assertEqual([service.item for service in plugin.discovery_function(**kwargs)], [kind])
                results = list(plugin.check_function(item=kind, **kwargs))
                self.assertEqual(metrics(results)['fortisase_sessions'], count)
                self.assertEqual({result.state for result in results if hasattr(result, 'state')}, {api.State.OK})

    def test_collection_scope_includes_license_without_sso_endpoints_or_ztna(self):
        """
        Verify all monitored resource groups are collected without querying schemas.

        Input:
            The special agent's configured resource sections.

        Output:
            Fourteen resource groups including private-access health, region metadata and identity providers.

        """
        self.assertEqual(len(agent.SECTIONS), 14)
        self.assertEqual(set(path for path, _ in agent.SECTIONS.values()), {
            '/monitor-api/v1/traffic-history', '/monitor-api/v1/user/swg/sessions',
            '/monitor-api/v1/user/vpn/sessions',
            '/resource-api/v2/system/certificate/remote-certificates',
            agent.SEATS_ENDPOINT, agent.CONNECTIONS_ENDPOINT, agent.HEALTH_ENDPOINT, agent.IDP_ENDPOINT, agent.REGIONS_ENDPOINT})

    def test_registration_names_are_unique_and_default_sections_exist(self):
        """
        Verify registration names are unique and default sections exist.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        modules = (status, certs, swg, vpn, traffic, pop, license_check, private_access, idp)
        sections = [v.name for m in modules for k, v in vars(m).items() if k.startswith('agent_section_')]
        plugins = [v for m in modules for k, v in vars(m).items() if k.startswith('check_plugin_')]
        self.assertEqual(len(sections), len(set(sections)))
        self.assertEqual(len(plugins), len({plugin.name for plugin in plugins}))
        for plugin in plugins:
            for section in getattr(plugin, 'sections', [plugin.name]):
                self.assertIn(section, sections)
        self.assertEqual(set(sections), set(agent.SECTIONS) | {'fortisase_api'})


def seat_response(seats=50, used=1):
    """
    Seat response.

    Input:
        seats: Licensed capacity, default 50.
        used: Allocated seats, default 1.

    Output:
        Successful seat API response fixture using the result/data envelope.

    """
    return {'result': {'retval': 1, 'message': None}, 'data': {'seats': seats, 'used': used}}


class LicenseTests(unittest.TestCase):
    """
    Licensetests.

    Input:
        Test-runner constructor arguments and test fixtures defined by this class.

    Output:
        Test case instance validating the documented monitoring behavior.

    """
    def test_supplied_response_produces_counts_and_two_percent_usage(self):
        """
        Verify supplied response produces counts and two percent usage.

        Input:
            self: Test case instance; mocked API responses and scenario data defined in the test.

        Output:
            None; assertions verify expected states, metrics or transport behavior and fail on regressions.

        """
        section = parsed(parse_license, seat_response())
        self.assertEqual(len(list(license_check.discover_license(section))), 1)
        results = list(license_check.check_license(section))
        self.assertEqual(results[0].state, api.State.OK)
        self.assertEqual(metrics(results), {'fortisase_license_seats': 50,
            'fortisase_license_used': 1, 'fortisase_license_free': 49, 'fortisase_license_usage': 2.0})

    def test_capacity_thresholds_full_and_overallocated(self):
        """
        Verify capacity thresholds full and overallocated.

        Input:
            self: Test case instance; mocked API responses and scenario data defined in the test.

        Output:
            None; assertions verify expected states, metrics or transport behavior and fail on regressions.

        """
        for used, expected in ((44, api.State.OK), (45, api.State.WARN),
                               (49, api.State.WARN), (50, api.State.CRIT),
                               (51, api.State.CRIT)):
            with self.subTest(used=used):
                results = list(license_check.check_license(parsed(parse_license, seat_response(50, used))))
                self.assertEqual(results[0].state, expected)
                self.assertGreaterEqual(metrics(results)['fortisase_license_free'], 0)

    def test_zero_capacity_does_not_invent_percentage(self):
        """
        Verify zero capacity does not invent percentage.

        Input:
            self: Test case instance; mocked API responses and scenario data defined in the test.

        Output:
            None; assertions verify expected states, metrics or transport behavior and fail on regressions.

        """
        for used, expected in ((0, api.State.WARN), (1, api.State.CRIT)):
            results = list(license_check.check_license(parsed(parse_license, seat_response(0, used))))
            self.assertEqual(results[0].state, expected)
            self.assertNotIn('fortisase_license_usage', metrics(results))
            self.assertEqual(metrics(results)['fortisase_license_free'], 0)

    def test_missing_invalid_counts_and_failure_envelopes_do_not_become_zero(self):
        """
        Verify missing invalid counts and failure envelopes do not become zero.

        Input:
            self: Test case instance; mocked API responses and scenario data defined in the test.

        Output:
            None; assertions verify expected states, metrics or transport behavior and fail on regressions.

        """
        invalid = [{}, {'data': {'seats': 50, 'used': 1}},
                   {'result': {'retval': 0}, 'data': {'seats': 50, 'used': 1}},
                   {'result': {'retval': True}, 'data': {'seats': 50, 'used': 1}}]
        for field in ('seats', 'used'):
            for value in (None, -1, True, '1', 1.5, float('inf'), 10 ** 400):
                raw = seat_response()
                raw['data'][field] = value
                invalid.append(raw)
        for raw in invalid:
            with self.subTest(raw=raw):
                results = list(license_check.check_license(parsed(parse_license, raw)))
                self.assertEqual(results[0].state, api.State.UNKNOWN)
                self.assertEqual(metrics(results), {})

    def test_transport_accepts_result_envelope_using_existing_oauth_token(self):
        """
        Verify transport accepts result envelope using existing oauth token.

        Input:
            self: Test case instance; mocked API responses and scenario data defined in the test.

        Output:
            None; assertions verify expected states, metrics or transport behavior and fail on regressions.

        """
        with tempfile.TemporaryDirectory() as directory, patch.object(
                agent, '_cache_dir', return_value=Path(directory)):
            args = agent.parse_arguments(['--api-id', 'example', '--password-from-stdin'])
            client = agent.FortiSASEClient(args, 'test-password')
            self.addCleanup(client.session.close)
            client._token = 'collector-token'
            with patch.object(client, '_request', return_value=response(seat_response())) as request:
                result = client.get(agent.SEATS_ENDPOINT)
            self.assertEqual(result['data']['used'], 1)
            self.assertEqual(request.call_args.args, ('get', client.base_url + agent.SEATS_ENDPOINT))
            self.assertEqual(request.call_args.kwargs['headers']['Authorization'], 'Bearer collector-token')
            self.assertNotIn('Cookie', request.call_args.kwargs['headers'])

    def test_transport_rejects_http_200_application_failure(self):
        """
        Verify transport rejects http 200 application failure.

        Input:
            self: Test case instance; mocked API responses and scenario data defined in the test.

        Output:
            None; assertions verify expected states, metrics or transport behavior and fail on regressions.

        """
        with tempfile.TemporaryDirectory() as directory, patch.object(
                agent, '_cache_dir', return_value=Path(directory)):
            args = agent.parse_arguments(['--api-id', 'example', '--password-from-stdin'])
            client = agent.FortiSASEClient(args, 'test-password')
            self.addCleanup(client.session.close)
            for retval in (None, 0, -1, True, '1'):
                with self.subTest(retval=retval), patch.object(client, '_request', return_value=response(
                        {'result': {'retval': retval}, 'data': {'seats': 50, 'used': 1}})):
                    with self.assertRaises(agent.APIError):
                        client.get(agent.SEATS_ENDPOINT)

    def test_denied_license_request_preserves_other_services(self):
        """
        Verify denied license request preserves other services.

        Input:
            self: Test case instance; mocked API responses and scenario data defined in the test.

        Output:
            None; assertions verify expected states, metrics or transport behavior and fail on regressions.

        """
        client = Mock()
        def get(path, params):
            """
            Get.

            Input:
                path: Requested resource API path.
                params: Resource query parameters, or None.

            Output:
                Mock API response; raises APIError for the endpoint deliberately denied by the test.

            """
            if path == agent.REGIONS_ENDPOINT:
                return {'data': {'sites': {'federated_sites': []}}}
            if path == agent.IDP_ENDPOINT:
                return {'result': {'retval': 1}, 'data': []}
            if path == agent.CONNECTIONS_ENDPOINT:
                return {'hubs': []}
            if path == agent.SEATS_ENDPOINT:
                raise agent.APIError('API request failed (HTTP 403)')
            return {'data': []}
        client.get.side_effect = get
        output = io.StringIO()
        with redirect_stdout(output):
            agent.collect(client)
        lines = output.getvalue().splitlines()
        report = json.loads(lines[-1])
        self.assertEqual(report['successful'], 13)
        self.assertEqual(report['total'], 14)
        self.assertNotIn('<<<fortisase_license:sep(0)>>>', lines)
        self.assertIn('<<<fortisase_swg_sessions:sep(0)>>>', lines)


class PrivateAccessTests(unittest.TestCase):
    """
    Exercise hub correlation, node failures, measurement limits and API envelopes.

    Input:
        Test-runner constructor arguments and test fixtures defined by this class.

    Output:
        Test case instance validating the documented monitoring behavior.

    """
    def setUp(self):
        """
        Prepare an anonymized two-node hub fixture matching the supplied schema.

        Input:
            self: Private-access test case created by the unittest runner.

        Output:
            None; initializes anonymized hub configuration and two reporting-node fixtures.

        """
        self.connections = {'code': 200, 'hubs': [{
            'seq_num': 1, 'config_state': 'success',
            'config': {'alias': 'Test Hub', 'bgp_peer_ip': '192.0.2.254', 'auth': 'not-exported'},
            'common_config': {'internal': 'not-exported'},
        }]}
        self.health = {'code': 200, 'data': [{
            'primaryKey': serial,
            'health': {'hub1': {'status': 'up', 'latency': latency, 'jitter': 0.5, 'packetLoss': 0.0}},
            'vpnTunnel': {'hub1': 'up', 'default-ipsec': 'down', 'unrelated': 'down'},
            'bgpNeighbors': {'192.0.2.254': 'Established', '192.0.2.123': 'Idle'},
        } for serial, latency in [('node-a', 6.0), ('node-b', 143.5)]]}

    def results(self, kind, params=None):
        """
        Run registered checks with Checkmk-style named section binding.

        Input:
            kind: vpn, bgp or health check.
            params: Optional link thresholds; defaults to the plugin levels.

        Output:
            Materialized check results and metrics evaluated from the current test fixtures.

        """
        args = dict(item='Test Hub',
                    section_fortisase_private_access_connections=parsed(
                        private_access.parse_connections, self.connections),
                    section_fortisase_private_access_health=parsed(private_access.parse_health, self.health))
        if kind == 'health':
            args['params'] = params or private_access.DEFAULT_LEVELS
        return list(getattr(private_access, 'check_' + kind)(**args))

    def test_discovery_and_unrelated_down_tunnels(self):
        """
        Discover the alias once and ignore tunnel/neighbor states of other hubs.

        Input:
            self: Test case instance; mocked API responses and scenario data defined in the test.

        Output:
            None; assertions verify expected states, metrics or transport behavior and fail on regressions.

        """
        hubs = parsed(private_access.parse_connections, self.connections)
        found = list(private_access.discover_private_access(hubs, None))
        self.assertEqual([service.item for service in found], ['Test Hub'])
        for kind in ('vpn', 'bgp', 'health'):
            with self.subTest(kind=kind):
                results = self.results(kind)
                self.assertTrue(all(r.state == api.State.OK for r in results if hasattr(r, 'state')))
                self.assertEqual(metrics(results)['fortisase_private_access_nodes'], 2)
        self.assertEqual(metrics(self.results('health'))['fortisase_private_access_latency'], 143.5)
        self.assertEqual(metrics(self.results('health'))['fortisase_private_access_packet_loss'], 0.0)

    def test_one_failed_node_is_critical(self):
        """
        Retain failures even when the other node reports a healthy connection.

        Input:
            self: Test case instance; mocked API responses and scenario data defined in the test.

        Output:
            None; assertions verify expected states, metrics or transport behavior and fail on regressions.

        """
        for kind, field, value in [('vpn', 'vpnTunnel', 'down'), ('bgp', 'bgpNeighbors', 'Idle')]:
            key = 'hub1' if kind == 'vpn' else '192.0.2.254'
            self.health['data'][1][field][key] = value
            self.assertIn(api.State.CRIT, [r.state for r in self.results(kind) if hasattr(r, 'state')])
        self.health['data'][1]['health']['hub1']['status'] = 'down'
        self.assertIn(api.State.CRIT, [r.state for r in self.results('health') if hasattr(r, 'state')])

    def test_unknown_and_missing_node_data(self):
        """
        Report absent or unrecognized states as UNKNOWN rather than healthy.

        Input:
            self: Test case instance; mocked API responses and scenario data defined in the test.

        Output:
            None; assertions verify expected states, metrics or transport behavior and fail on regressions.

        """
        for kind in ('vpn', 'bgp', 'health'):
            original = self.health['data']
            self.health['data'] = []
            self.assertEqual(self.results(kind)[0].state, api.State.UNKNOWN)
            self.health['data'] = original
        self.health['data'][1]['vpnTunnel']['hub1'] = 'unexpected'
        self.assertIn(api.State.UNKNOWN, [r.state for r in self.results('vpn') if hasattr(r, 'state')])
        del self.health['data'][1]['bgpNeighbors']['192.0.2.254']
        self.assertIn(api.State.UNKNOWN, [r.state for r in self.results('bgp') if hasattr(r, 'state')])

    def test_config_failure_and_missing_hub(self):
        """
        Surface failed provisioning and stale discovered hub items.

        Input:
            self: Test case instance; mocked API responses and scenario data defined in the test.

        Output:
            None; assertions verify expected states, metrics or transport behavior and fail on regressions.

        """
        self.connections['hubs'][0]['config_state'] = 'failed'
        self.assertEqual(self.results('vpn')[0].state, api.State.CRIT)
        self.connections['hubs'] = []
        self.assertEqual(self.results('vpn')[0].state, api.State.UNKNOWN)

    def test_link_thresholds_and_invalid_measurements(self):
        """
        Check exact upper boundaries, configurable limits and malformed samples.

        Input:
            self: Test case instance; mocked API responses and scenario data defined in the test.

        Output:
            None; assertions verify expected states, metrics or transport behavior and fail on regressions.

        """
        link = self.health['data'][1]['health']['hub1']
        for value, expected in [(150.0, api.State.WARN), (300.0, api.State.CRIT)]:
            link['latency'] = value
            self.assertIn(expected, [r.state for r in self.results('health') if hasattr(r, 'state')])
        link['latency'] = 100.0
        limits = dict(private_access.DEFAULT_LEVELS, latency=('fixed', (50.0, 90.0)))
        self.assertIn(api.State.CRIT, [r.state for r in self.results('health', limits) if hasattr(r, 'state')])
        for value in (None, True, -1, 'bad'):
            link['jitter'] = value
            self.assertIn(api.State.UNKNOWN, [r.state for r in self.results('health') if hasattr(r, 'state')])
        link['packetLoss'] = 101
        self.assertIn(api.State.UNKNOWN, [r.state for r in self.results('health') if hasattr(r, 'state')])

    def test_ambiguous_hubs_and_nodes_are_rejected(self):
        """
        Reject duplicate identities and malformed response envelopes.

        Input:
            self: Test case instance; mocked API responses and scenario data defined in the test.

        Output:
            None; assertions verify expected states, metrics or transport behavior and fail on regressions.

        """
        self.connections['hubs'] *= 2
        self.assertIsNone(parsed(private_access.parse_connections, self.connections))
        self.health['data'] *= 2
        self.assertIsNone(parsed(private_access.parse_health, self.health))
        for parser in (private_access.parse_connections, private_access.parse_health):
            self.assertIsNone(parser([['invalid json']]))
            self.assertIsNone(parsed(parser, {'code': 403, 'data': []}))

    def test_transport_accepts_hubs_envelope_and_filters_configuration(self):
        """
        Use existing OAuth authentication without retaining configuration secrets.

        Input:
            self: Test case instance; mocked API responses and scenario data defined in the test.

        Output:
            None; assertions verify expected states, metrics or transport behavior and fail on regressions.

        """
        with tempfile.TemporaryDirectory() as directory, patch.object(
                agent, '_cache_dir', return_value=Path(directory)):
            client = agent.FortiSASEClient(agent.parse_arguments(
                ['--api-id', 'example', '--password-from-stdin']), 'test-password')
            self.addCleanup(client.session.close)
            client._token = 'collector-token'
            with patch.object(client, '_request', return_value=response(self.connections)):
                raw = client.get(agent.CONNECTIONS_ENDPOINT)
            filtered = agent.monitoring_payload('fortisase_private_access_connections', raw)
            self.assertNotIn('not-exported', json.dumps(filtered))
            self.assertEqual(parsed(private_access.parse_connections, filtered)['Test Hub']['key'], 'hub1')

    def test_sequence_number_selects_only_its_hub(self):
        """
        Resolve non-positional hub keys and reject a missing configured BGP peer.

        Input:
            self: Test case instance; mocked API responses and scenario data defined in the test.

        Output:
            None; assertions verify expected states, metrics or transport behavior and fail on regressions.

        """
        self.connections['hubs'][0]['seq_num'] = 7
        for node in self.health['data']:
            node['health']['hub7'] = node['health'].pop('hub1')
            node['vpnTunnel']['hub7'] = node['vpnTunnel'].pop('hub1')
            node['vpnTunnel']['hub1'] = 'down'
        self.assertTrue(all(r.state == api.State.OK for r in self.results('vpn') if hasattr(r, 'state')))
        self.connections['hubs'][0]['config'].pop('bgp_peer_ip')
        self.assertIn(api.State.UNKNOWN, [r.state for r in self.results('bgp') if hasattr(r, 'state')])

    def test_access_denied_preserves_existing_services(self):
        """
        Keep other services and API diagnostics when private-access access is denied.

        Input:
            self: Test case instance; mocked API responses and scenario data defined in the test.

        Output:
            None; assertions verify expected states, metrics or transport behavior and fail on regressions.

        """
        client = Mock()
        def get(path, params):
            """
            Get.

            Input:
                path: Requested resource API path.
                params: Resource query parameters, or None.

            Output:
                Mock API response; raises APIError for the endpoint deliberately denied by the test.

            """
            if path == agent.REGIONS_ENDPOINT:
                return {'data': {'sites': {'federated_sites': []}}}
            if path == agent.IDP_ENDPOINT:
                return {'result': {'retval': 1}, 'data': []}
            if path in (agent.CONNECTIONS_ENDPOINT, agent.HEALTH_ENDPOINT):
                raise agent.APIError('API request failed (HTTP 403)')
            if path == agent.SEATS_ENDPOINT:
                return seat_response()
            return {'data': []}
        client.get.side_effect = get
        output = io.StringIO()
        with redirect_stdout(output):
            agent.collect(client)
        lines = output.getvalue().splitlines()
        report = json.loads(lines[-1])
        self.assertEqual((report['successful'], report['total']), (12, 14))
        self.assertEqual(len(report['errors']), 2)
        self.assertIn('<<<fortisase_license:sep(0)>>>', lines)


class IdentityProviderTests(unittest.TestCase):
    """
    Verify EMS-compatible provider availability, rendering and synchronization checks.

    Input:
        Anonymized provider records matching the supplied FortiSASE response.

    Output:
        Assertions for domain/GUID output, metrics, error states and API isolation.
    """
    def setUp(self):
        """
        Prepare a successful directory synchronization snapshot.

        Input:
            self: Test case created by unittest.

        Output:
            Response fixture and a fixed UTC evaluation time.
        """
        self.now = datetime(2026, 11, 7, 12, 58, 14, tzinfo=timezone.utc)
        self.entry = {
            'guid': '00000000-0000-4000-8000-000000000001',
            'total_devices': 27, 'total_users': 5,
            'connection_info': {'conn_online': True, 'alias': None, 'user': 'not-exported'},
            'status': {'online': True, 'last_error': '', 'sync_progress': 100,
                       'last_success_enumerated': '2026-11-07T12:33:05'},
            'domain_info': {'name': 'example.test', 'guid': '00000000-0000-4000-8000-000000000001'},
            'group_info': {'path': 'example.test'},
        }
        self.response = {'result': {'retval': 1, 'message': None}, 'data': [self.entry]}

    def results(self, params=None):
        """
        Evaluate the current response using deterministic UTC time.

        Input:
            params: Optional IDP check parameter overrides.

        Output:
            Materialized check results and metrics for example.test.
        """
        section = parsed(idp.parse_idps, self.response)
        with patch.object(idp, 'datetime', wraps=datetime) as clock:
            clock.now.return_value = self.now
            return list(idp.check_idp('example.test', params or idp.DEFAULT_PARAMETERS, section))

    def test_domain_guid_and_ems_style_output(self):
        """
        Preserve the EMS rendering and all requested provider measurements.

        Input:
            Successful provider with a timezone-less UTC sync timestamp.

        Output:
            Readable item, healthy status, counts, progress and sync age in seconds.
        """
        section = parsed(idp.parse_idps, self.response)
        self.assertEqual([s.item for s in idp.discover_idps(section)], ['example.test'])
        results = self.results()
        summaries = [r.summary for r in results if hasattr(r, 'state')]
        for expected in ('Domain: example.test', 'GUID: '+self.entry['guid'], 'IDP: online',
                         'Connector: online', 'No synchronization error', 'Devices: 27', 'Users: 5',
                         'Sync progress: 100%', 'Last successful sync: 2026-11-07T12:33:05+00:00'):
            self.assertIn(expected, summaries)
        self.assertTrue(all(r.state == api.State.OK for r in results if hasattr(r, 'state')))
        self.assertEqual(metrics(results), {'fortisase_idp_devices': 27, 'fortisase_idp_users': 5,
                         'fortisase_idp_sync_progress': 100, 'fortisase_idp_sync_age': 1509})

    def test_offline_connector_and_sync_error_states(self):
        """
        Honor configurable failure severity for provider and connector outages.

        Input:
            Offline IDP/connector or a non-empty synchronization error.

        Output:
            CRIT by default, WARN when the corresponding rule is changed.
        """
        for container, key, value, setting in (
                ('status', 'online', False, 'offline_state'),
                ('connection_info', 'conn_online', False, 'connector_state'),
                ('status', 'last_error', 'Directory unavailable', 'error_state')):
            original = self.entry[container][key]
            self.entry[container][key] = value
            self.assertIn(api.State.CRIT, [r.state for r in self.results() if hasattr(r, 'state')])
            params = dict(idp.DEFAULT_PARAMETERS, **{setting: 'warn'})
            states = [r.state for r in self.results(params) if hasattr(r, 'state')]
            self.assertIn(api.State.WARN, states)
            self.assertNotIn(api.State.CRIT, states)
            self.entry[container][key] = original

    def test_sync_age_thresholds(self):
        """
        Evaluate upper synchronization age boundaries in seconds.

        Input:
            Last successful synchronization exactly one or two days ago.

        Output:
            WARN after 24 hours and CRIT after 48 hours.
        """
        for stamp, state in [('2026-11-06T12:58:14Z', api.State.WARN),
                             ('2026-11-05T12:58:14+00:00', api.State.CRIT)]:
            self.entry['status']['last_success_enumerated'] = stamp
            self.assertIn(state, [r.state for r in self.results() if hasattr(r, 'state')])

    def test_missing_future_dates_and_invalid_measurements(self):
        """
        Reject missing/future timestamps and malformed status measurements.

        Input:
            Missing, invalid and future sync dates; invalid progress and counters.

        Output:
            UNKNOWN diagnostics with no fabricated values or negative sync age.
        """
        for stamp in (None, 'bad', '2026-11-08T12:58:14Z'):
            self.entry['status']['last_success_enumerated'] = stamp
            results = self.results()
            self.assertIn(api.State.UNKNOWN, [r.state for r in results if hasattr(r, 'state')])
            self.assertNotIn('fortisase_idp_sync_age', metrics(results))
        self.entry['status']['last_success_enumerated'] = '2026-11-07T12:33:05'
        self.entry['status']['sync_progress'] = 101
        self.entry['total_devices'] = True
        self.entry['connection_info']['conn_online'] = None
        results = self.results()
        self.assertIn(api.State.UNKNOWN, [r.state for r in results if hasattr(r, 'state')])
        self.assertNotIn('fortisase_idp_devices', metrics(results))
        self.assertNotIn('fortisase_idp_sync_progress', metrics(results))

    def test_empty_invalid_and_ambiguous_inventory(self):
        """
        Distinguish no providers from invalid API data and duplicate names.

        Input:
            Empty successful inventory, duplicate entries and failed API envelopes.

        Output:
            Zero inventory is healthy; ambiguous/invalid records remain UNKNOWN.
        """
        empty = parsed(idp.parse_idps, {'result': {'retval': 1}, 'data': []})
        self.assertEqual(list(idp.discover_idps(empty)), [])
        self.assertEqual(metrics(list(idp.check_summary(empty)))['fortisase_idp_count'], 0)
        self.response['data'] *= 2
        section = parsed(idp.parse_idps, self.response)
        self.assertEqual(list(idp.check_summary(section))[0].state, api.State.UNKNOWN)
        self.assertEqual(list(idp.check_idp('example.test', {}, section))[0].state, api.State.UNKNOWN)
        for retval in (None, 0, True, '1'):
            invalid = parsed(idp.parse_idps, {'result': {'retval': retval}, 'data': []})
            self.assertEqual(list(idp.check_summary(invalid))[0].state, api.State.UNKNOWN)

    def test_transport_validation_and_whitelist(self):
        """
        Fetch the IDP envelope using OAuth and omit unrelated connector fields.

        Input:
            Successful and failed application responses returned with HTTP 200.

        Output:
            Accepted response with monitoring-only output; failures raise APIError.
        """
        with tempfile.TemporaryDirectory() as directory, patch.object(
                agent, '_cache_dir', return_value=Path(directory)):
            client = agent.FortiSASEClient(agent.parse_arguments(
                ['--api-id', 'example', '--password-from-stdin']), 'test-password')
            self.addCleanup(client.session.close)
            client._token = 'collector-token'
            with patch.object(client, '_request', return_value=response(self.response)) as request:
                raw = client.get(agent.IDP_ENDPOINT)
                self.assertEqual(request.call_args.kwargs['headers']['Authorization'], 'Bearer collector-token')
            filtered = agent.monitoring_payload('fortisase_idp', raw)
            self.assertNotIn('not-exported', json.dumps(filtered))
            self.assertEqual(parsed(idp.parse_idps, filtered)['count'], 1)
            client._memo.clear()
            with patch.object(client, '_request', return_value=response({'result': {'retval': 0}, 'data': []})):
                with self.assertRaises(agent.APIError):
                    client.get(agent.IDP_ENDPOINT)

    def test_empty_idp_payload_forms_remain_successful(self):
        """
        Accept explicit empty payloads when no provider is configured.

        Input:
            Successful IDP responses with data null, an empty object or an empty list.

        Output:
            Successful collection, zero inventory and no discovered IDP items.
        """
        with tempfile.TemporaryDirectory() as directory, patch.object(
                agent, '_cache_dir', return_value=Path(directory)):
            client = agent.FortiSASEClient(agent.parse_arguments(
                ['--api-id', 'example', '--password-from-stdin']), 'test-password')
            self.addCleanup(client.session.close)
            client._token = 'collector-token'
            for value in (None, {}, []):
                with self.subTest(data=value):
                    raw = {'result': {'retval': 1}, 'data': value}
                    client._memo.clear()
                    with patch.object(client, '_request', return_value=response(raw)):
                        accepted = client.get(agent.IDP_ENDPOINT)
                    filtered = agent.monitoring_payload('fortisase_idp', accepted)
                    self.assertEqual(filtered['data'], [])
                    self.assertEqual(agent.monitoring_payload('fortisase_idp', raw)['data'], [])
                    section = parsed(idp.parse_idps, raw)
                    self.assertTrue(section['valid'])
                    self.assertEqual(list(idp.discover_idps(section)), [])
                    results = list(idp.check_summary(section))
                    self.assertEqual(results[0].state, api.State.OK)
                    self.assertEqual(metrics(results)['fortisase_idp_count'], 0)

    def test_missing_and_nonempty_invalid_idp_payloads_remain_errors(self):
        """
        Do not turn application failures or unsupported data shapes into empty inventories.

        Input:
            Missing data, non-empty objects, scalar values and failed retval values.

        Output:
            Transport/API errors and UNKNOWN inventory diagnostics.
        """
        cases = [{'result': {'retval': 1}},
                 *[{'result': {'retval': 1}, 'data': value}
                   for value in ({'unexpected': []}, '', 0, False)],
                 *[{'result': {'retval': value}, 'data': None} for value in (0, True, '1')]]
        with tempfile.TemporaryDirectory() as directory, patch.object(
                agent, '_cache_dir', return_value=Path(directory)):
            client = agent.FortiSASEClient(agent.parse_arguments(
                ['--api-id', 'example', '--password-from-stdin']), 'test-password')
            self.addCleanup(client.session.close)
            for raw in cases:
                with self.subTest(raw=raw), patch.object(client, '_request', return_value=response(raw)):
                    client._memo.clear()
                    with self.assertRaises(agent.APIError):
                        client.get(agent.IDP_ENDPOINT)
                    with self.assertRaises(agent.APIError):
                        agent.monitoring_payload('fortisase_idp', raw)
                    section = parsed(idp.parse_idps, raw)
                    self.assertFalse(section['valid'])
                    self.assertEqual(list(idp.check_summary(section))[0].state, api.State.UNKNOWN)

    def test_unexpected_idp_structure_skips_discovery_without_api_warning(self):
        """Skip unsupported IDP payloads while retaining healthy API coverage."""
        with tempfile.TemporaryDirectory() as directory, patch.object(
                agent, '_cache_dir', return_value=Path(directory)):
            client = agent.FortiSASEClient(agent.parse_arguments(
                ['--api-id', 'example', '--password-from-stdin']), 'test-password')
            self.addCleanup(client.session.close)
            for payload in ({'result': {'retval': 1}},
                            {'result': {'retval': 1}, 'data': ''},
                            {'result': {'retval': 1}, 'data': {'unexpected': []}}):
                with self.subTest(payload=payload):
                    client._memo.clear()
                    output = io.StringIO()
                    sections = {'fortisase_idp': (agent.IDP_ENDPOINT, None),
                                'fortisase_vpn_sessions': ('/test/sessions', None)}
                    with patch.object(agent, 'SECTIONS', sections), patch.object(
                            client, 'authenticate'), patch.object(client, '_request', side_effect=[
                                response(payload), response({'data': []})]), redirect_stdout(output):
                        agent.collect(client)
                    lines = output.getvalue().splitlines()
                    self.assertNotIn('<<<fortisase_idp:sep(0)>>>', lines)
                    self.assertIn('<<<fortisase_vpn_sessions:sep(0)>>>', lines)
                    report = json.loads(lines[-1])
                    self.assertEqual(report['errors'], [])
                    self.assertEqual((report['successful'], report['total']), (1, 1))
                    self.assertEqual(list(status.check_api(report))[0].state, api.State.OK)

    def test_denied_idp_query_preserves_other_sections(self):
        """
        Isolate a denied IDP endpoint from existing monitoring services.

        Input:
            Collector fixture returning HTTP 403 only for the IDP API.

        Output:
            Twelve successful queries, one API error and preserved session sections.
        """
        client = Mock()
        def get(path, params):
            """
            Return supported envelopes for all resources except IDP.

            Input:
                path: Resource endpoint; params: Optional traffic query.

            Output:
                Successful fixture or APIError for the deliberately denied endpoint.
            """
            if path == agent.REGIONS_ENDPOINT:
                return {'data': {'sites': {'federated_sites': []}}}
            if path == agent.IDP_ENDPOINT:
                raise agent.APIError('API request failed (HTTP 403)')
            if path == agent.CONNECTIONS_ENDPOINT:
                return {'hubs': []}
            if path == agent.SEATS_ENDPOINT:
                return seat_response()
            return {'data': []}
        client.get.side_effect = get
        output = io.StringIO()
        with redirect_stdout(output):
            agent.collect(client)
        lines = output.getvalue().splitlines()
        report = json.loads(lines[-1])
        self.assertEqual((report['successful'], report['total']), (13, 14))
        self.assertEqual(len(report['errors']), 1)
        self.assertIn('<<<fortisase_vpn_sessions:sep(0)>>>', lines)


class RegionAliasTests(unittest.TestCase):
    """
    Verify stable node identity joins and readable private-access location output.

    Input:
        Hub/node fixtures plus admin-config site metadata.

    Output:
        Assertions for city/datacenter labels, sanitization and safe fallbacks.
    """
    setUp = PrivateAccessTests.setUp

    def config(self):
        """
        Build nested metadata independent of health record ordering.

        Input:
            None; node-b is deliberately listed before node-a.

        Output:
            Admin-config response containing duplicate nested site references.
        """
        return {'code': 200, 'data': {'context': {'secret': 'not-exported'}, 'sites': {
            'invitation_code': 'not-exported',
            'federated_sites': [
                {'device_sn': 'node-b', 'region_alias': 'Bangalore (India) (F)',
                 'pop_airport_name': 'blr-f1', 'invitation_code': 'not-exported'},
                {'device_sn': 'node-a', 'region_alias': 'Zurich (Switzerland) (G)',
                 'pop_airport_name': 'zrh-g2'}],
            'config': {'slaves': [{'sites': [
                {'device_sn': 'node-b', 'region_alias': 'Bangalore (India) (F)'}]}]},
        }}}

    def test_all_three_checks_use_city_and_datacenter(self):
        """
        Render node labels by serial identity while preserving raw IDs in details.

        Input:
            Two node identities and reversed-order site metadata.

        Output:
            Zurich/Bangalore labels in VPN, BGP and health summaries.
        """
        regions = parsed(private_access.parse_regions, agent.region_payload(self.config()))
        self.assertEqual(regions, {'node-a': 'Zurich (zrh-g2)', 'node-b': 'Bangalore (blr-f1)'})
        for kind in ('vpn', 'bgp', 'health'):
            results = list(private_access.evaluate('Test Hub',
                parsed(private_access.parse_connections, self.connections),
                parsed(private_access.parse_health, self.health), kind, regions=regions))
            summaries = [r.summary for r in results if hasattr(r, 'state')]
            self.assertTrue(any(line.startswith('Zurich (zrh-g2):') for line in summaries))
            self.assertTrue(any(line.startswith('Bangalore (blr-f1):') for line in summaries))
            self.assertFalse(any('node-a' in line or 'node-b' in line for line in summaries))
            self.assertTrue(any('Node: node-a' in r.details for r in results if hasattr(r, 'details')))
            kwargs = {'item': 'Test Hub', 'section_fortisase_private_access_connections':
                parsed(private_access.parse_connections, self.connections),
                'section_fortisase_private_access_health': parsed(private_access.parse_health, self.health),
                'section_fortisase_regions': regions}
            if kind == 'health':
                kwargs['params'] = private_access.DEFAULT_LEVELS
            registered = list(getattr(private_access, 'check_'+kind)(**kwargs))
            self.assertTrue(any(getattr(r, 'summary', '').startswith('Bangalore (blr-f1):') for r in registered))

    def test_invalid_measurements_use_location_label(self):
        """
        Keep location naming consistent in error messages as well as healthy states.

        Input:
            Missing jitter on a known node.

        Output:
            UNKNOWN message prefixed by city/datacenter instead of serial number.
        """
        self.health['data'][0]['health']['hub1']['jitter'] = None
        results = list(private_access.evaluate('Test Hub',
            parsed(private_access.parse_connections, self.connections),
            parsed(private_access.parse_health, self.health), 'health',
            regions={'node-a': 'Zurich (zrh-g2)'}))
        self.assertTrue(any(getattr(r, 'summary', '') == 'Zurich (zrh-g2): missing or invalid jitter'
                            for r in results))

    def test_missing_or_conflicting_metadata_falls_back_to_serial(self):
        """
        Avoid assigning a node to a guessed region when metadata is incomplete.

        Input:
            Failed metadata envelope, missing datacenter and contradictory aliases.

        Output:
            Empty/partial mappings with stable serial fallback and unchanged health.
        """
        self.assertEqual(parsed(private_access.parse_regions, {'code': 403, 'data': []}), {})
        self.assertEqual(private_access.parse_regions([['broken']]), {})
        raw = agent.region_payload(self.config())
        raw['data'].append({'device_sn': 'node-a', 'region_alias': 'Other', 'pop_airport_name': 'other-g1'})
        regions = parsed(private_access.parse_regions, raw)
        self.assertNotIn('node-a', regions)
        results = list(private_access.evaluate('Test Hub',
            parsed(private_access.parse_connections, self.connections),
            parsed(private_access.parse_health, self.health), 'vpn', regions=regions))
        self.assertTrue(any(getattr(r, 'summary', '').startswith('node-a:') for r in results))
        self.assertTrue(all(r.state == api.State.OK for r in results if hasattr(r, 'state')))
        only_alias = parsed(private_access.parse_regions, {'data': [
            {'device_sn': 'node-a', 'region_alias': 'Zurich (Switzerland) (G)'}]})
        self.assertEqual(only_alias['node-a'], 'Zurich (Switzerland) (G)')

    def test_metadata_transport_and_whitelist(self):
        """
        Accept the object response and export only node/region naming fields.

        Input:
            Admin-config response with unrelated sensitive tenant configuration.

        Output:
            Validated OAuth request, include_sites query and sanitized labels.
        """
        with tempfile.TemporaryDirectory() as directory, patch.object(
                agent, '_cache_dir', return_value=Path(directory)):
            client = agent.FortiSASEClient(agent.parse_arguments(
                ['--api-id', 'example', '--password-from-stdin']), 'test-password')
            self.addCleanup(client.session.close)
            client._token = 'collector-token'
            with patch.object(client, '_request', return_value=response(self.config())) as request:
                raw = client.get(agent.REGIONS_ENDPOINT, {'include_sites': 'true'})
                self.assertEqual(request.call_args.kwargs['params'], {'include_sites': 'true'})
            filtered = agent.monitoring_payload('fortisase_regions', raw)
            self.assertNotIn('not-exported', json.dumps(filtered))
            self.assertEqual(len(parsed(private_access.parse_regions, filtered)), 2)
            with self.assertRaises(agent.APIError):
                agent.region_payload({'data': {'sites': []}})

    def test_denied_region_query_preserves_private_access_sections(self):
        """
        Isolate missing naming metadata from existing hub monitoring data.

        Input:
            HTTP 403 for admin/config while hub and health endpoints succeed.

        Output:
            API warning data, preserved private-access sections and no region section.
        """
        client = Mock()
        def get(path, params):
            """
            Return valid fixtures except for the deliberately denied config endpoint.

            Input:
                path: Requested endpoint; params: Optional query parameters.

            Output:
                API fixture or APIError for unavailable region metadata.
            """
            if path == agent.REGIONS_ENDPOINT:
                raise agent.APIError('API request failed (HTTP 403)')
            if path == agent.CONNECTIONS_ENDPOINT:
                return self.connections
            if path == agent.HEALTH_ENDPOINT:
                return self.health
            if path == agent.IDP_ENDPOINT:
                return {'result': {'retval': 1}, 'data': []}
            if path == agent.SEATS_ENDPOINT:
                return seat_response()
            return {'data': []}
        client.get.side_effect = get
        output = io.StringIO()
        with redirect_stdout(output):
            agent.collect(client)
        lines = output.getvalue().splitlines()
        report = json.loads(lines[-1])
        self.assertEqual((report['successful'], report['total']), (13, 14))
        self.assertNotIn('<<<fortisase_regions:sep(0)>>>', lines)
        self.assertIn('<<<fortisase_private_access_health:sep(0)>>>', lines)


if __name__ == '__main__':
    unittest.main()

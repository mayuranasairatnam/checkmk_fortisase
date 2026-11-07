"""
FortiSASE datasource configuration.
"""
from cmk.rulesets.v1 import Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue, DictElement, Dictionary, Integer, Password, SingleChoice,
    SingleChoiceElement, String, migrate_to_password, validators,
)
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic


def migrate_connection_settings(value):
    """
    Discard retired portal and token-lifetime overrides from saved rules.

    Input:
        value: Persisted integration parameters before form validation.

    Output:
        A copy retaining credentials and supported settings; non-dictionaries pass through.

    """
    if not isinstance(value, dict):
        return value
    return {key: setting for key, setting in value.items() if key not in ('base_url', 'cache_ttl')}


def parameter_form():
    """
    Build the Checkmk configuration form for the special agent.

    Input:
        None.

    Output:
        Dictionary form specification with credentials, connection defaults and validation rules.

    """
    return Dictionary(migrate=migrate_connection_settings, elements={
        'api_id': DictElement(required=True, parameter_form=String(
            title=Title('API ID'),
            custom_validate=(validators.LengthInRange(min_value=1),))),
        'api_password': DictElement(required=True, parameter_form=Password(
            title=Title('API password'), migrate=migrate_to_password)),
        'timeout': DictElement(parameter_form=Integer(
            title=Title('Timeout per API request'), unit_symbol='seconds',
            prefill=DefaultValue(30),
            custom_validate=(validators.NumberInRange(min_value=1, max_value=300),))),
        'tls': DictElement(parameter_form=SingleChoice(
            title=Title('TLS certificate verification'), prefill=DefaultValue('verify'),
            elements=[SingleChoiceElement(name='verify', title=Title('Verify certificate')),
                      SingleChoiceElement(name='skip', title=Title('Skip certificate verification'))])),
    })


rule_spec_fortisase = SpecialAgent(
    name='fortisase', title=Title('FortiSASE'), topic=Topic.NETWORKING,
    parameter_form=parameter_form)

"""
Certificate lifetime thresholds.
"""
from cmk.rulesets.v1 import Label, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue, DictElement, Dictionary, Float, Integer, LevelDirection, SimpleLevels, SingleChoice, SingleChoiceElement, validators,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostAndItemCondition, Topic


def certificate_form():
    """
    Build the Checkmk configuration form for certificate lifetime levels.

    Input:
        None.

    Output:
        Dictionary form specification with lower warning and critical thresholds in days.

    """
    return Dictionary(elements={
        'days_remaining': DictElement(required=True, parameter_form=SimpleLevels(
            title=Title('Days until certificate expiry'), level_direction=LevelDirection.LOWER,
            form_spec_template=Integer(label=Label('days'),
                custom_validate=(validators.NumberInRange(min_value=0),)),
            prefill_fixed_levels=DefaultValue((30, 14)))),
    })


rule_spec_fortisase_cert_expiry = CheckParameters(
    name='fortisase_cert_expiry', title=Title('FortiSASE Certificate Expiry'),
    topic=Topic.NETWORKING, parameter_form=certificate_form,
    condition=HostAndItemCondition(item_title=Title('Certificate ID')))


def private_access_form():
    """
    Configure upper thresholds for worst-case private-access link measurements.

    Input:
        None; default upper levels are defined by the form.

    Output:
        Checkmk Dictionary form for latency, jitter and packet-loss thresholds.

    """
    return Dictionary(elements={
        key: DictElement(required=True, parameter_form=SimpleLevels(
            title=Title(title), level_direction=LevelDirection.UPPER,
            form_spec_template=Float(label=Label(unit),
                custom_validate=(validators.NumberInRange(min_value=0),)),
            prefill_fixed_levels=DefaultValue(levels)))
        for key, title, unit, levels in (
            ('latency', 'Maximum latency', 'ms', (150.0, 300.0)),
            ('jitter', 'Maximum jitter', 'ms', (30.0, 50.0)),
            ('packet_loss', 'Maximum packet loss', '%', (1.0, 5.0)))
    })


rule_spec_fortisase_private_access = CheckParameters(
    name='fortisase_private_access', title=Title('FortiSASE Private Access Link Health'),
    topic=Topic.NETWORKING, parameter_form=private_access_form,
    condition=HostAndItemCondition(item_title=Title('Hub name')))


def idp_form():
    """
    Configure provider/connector failure states and maximum synchronization age.

    Input:
        None; defaults match the FortiClient EMS IDP service.

    Output:
        Checkmk Dictionary form with state selectors and upper sync-age levels.
    """
    elements = {
        key: DictElement(required=True, parameter_form=SingleChoice(
            title=Title(title), prefill=DefaultValue('crit'),
            elements=[SingleChoiceElement(name='warn', title=Title('WARN')),
                      SingleChoiceElement(name='crit', title=Title('CRIT'))]))
        for key, title in (('offline_state', 'IDP offline'),
                           ('connector_state', 'Connector offline'),
                           ('error_state', 'Synchronization error'))
    }
    elements['sync_age'] = DictElement(required=True, parameter_form=SimpleLevels(
        title=Title('Time since last successful synchronization'),
        level_direction=LevelDirection.UPPER,
        form_spec_template=Float(label=Label('seconds'),
            custom_validate=(validators.NumberInRange(min_value=0),)),
        prefill_fixed_levels=DefaultValue((86400.0, 172800.0))))
    return Dictionary(elements=elements)


rule_spec_fortisase_idp = CheckParameters(
    name='fortisase_idp', title=Title('FortiSASE identity providers'),
    topic=Topic.APPLICATIONS, parameter_form=idp_form,
    condition=HostAndItemCondition(item_title=Title('Identity provider')))

"""
Certificate lifetime thresholds.
"""
from cmk.rulesets.v1 import Label, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue, DictElement, Dictionary, Integer, LevelDirection, SimpleLevels, validators,
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

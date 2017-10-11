from apparmor.aare import AARE
from apparmor.rule import BaseRule as AABaseRule
from apparmor.rule import BaseRuleset as AABaseRuleset
from apparmor.rule import (
    check_and_split_list,
    logprof_value_or_all,
    parse_comment,
    parse_modifiers,
    quote_if_needed
)
from comarmor.common import ComArmorBug, type_is_str

# setup module translations
from apparmor.translations import init_translation
_ = init_translation()


class BaseRule(AABaseRule):
    pass


class BaseRuleset(AABaseRuleset):
    pass

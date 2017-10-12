# ----------------------------------------------------------------------
#    Copyright (C) 2016 Christian Boltz <apparmor@cboltz.de>
#    Copyright (C) 2017 Ruffin White <roxfoxpox@gmail.com>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
# ----------------------------------------------------------------------

from apparmor.aare import AARE
from comarmor.regex import RE_PROFILE_TOPIC, strip_quotes
from comarmor.common import ComArmorBug, ComArmorException, type_is_str
from comarmor.rule import BaseRule, BaseRuleset
from comarmor.rule import (
    check_and_split_list,
    logprof_value_or_all,
    parse_modifiers,
    quote_if_needed
)

# setup module translations
from apparmor.translations import init_translation
_ = init_translation()


topic_permissions = ('p', 's', 'r')  # also defines the write order


class TopicRule(BaseRule):
    '''Class to handle and store a single topic rule'''

    # Nothing external should reference this class, all external users
    # should reference the class field TopicRule.ALL
    class __TopicAll(object):
        pass

    ALL = __TopicAll

    rule_name = 'topic'

    def __init__(self, path, perms,
                 audit=False, deny=False, allow_keyword=False, comment='', log_event=None):
        '''Initialize TopicRule

           Parameters:
           - path: string, AARE or TopicRule.ALL
           - perms: string, set of chars or TopicRule.ALL (must not contain exec mode)
        '''

        super(TopicRule, self).__init__(audit=audit, deny=deny, allow_keyword=allow_keyword,
                                        comment=comment, log_event=log_event)

        self.path, self.all_paths = self._aare_or_all(
            path, 'path', True, log_event)
        #  rulepart, partperms, is_path, log_event

        self.can_glob = not self.all_paths
        self.can_glob_ext = not self.all_paths
        self.can_edit = not self.all_paths

        if type_is_str(perms):
            perms, tmp_exec_perms = split_perms(perms, deny)
            if tmp_exec_perms:
                raise ComArmorBug('perms must not contain exec perms')
            elif not perms:
                raise ComArmorBug('perms must not be empty')
        elif (not isinstance(perms, set)) or (perms is None):
            raise ComArmorBug('perms must be a set', type(perms))

        self.perms, self.all_perms, unknown_items = check_and_split_list(
            perms, topic_permissions, TopicRule.ALL,
            'TopicRule', 'permissions', allow_empty_list=True)
        if unknown_items:
            raise ComArmorBug(
                'Passed unknown perms to TopicRule: %s' % str(unknown_items))

        self.original_perms = None  # might be set by aa-logprof / aa.py propose_topic_rules()

    @classmethod
    def _match(cls, raw_rule):
        return RE_PROFILE_TOPIC.search(raw_rule)

    @classmethod
    def _parse(cls, raw_rule):
        '''parse raw_rule and return TopicRule'''

        matches = cls._match(raw_rule)
        if not matches:
            raise ComArmorException(_("Invalid topic rule '%s'") % raw_rule)

        audit, deny, allow_keyword, comment = parse_modifiers(matches)

        if matches.group('path'):
            path = strip_quotes(matches.group('path'))
        else:
            raise ComArmorException(
                _("Invalid path in topic rule '%s'") % raw_rule)

        if matches.group('perms'):
            perms = matches.group('perms')
            perms, exec_perms = split_perms(perms, deny)
        else:
            raise ComArmorException(
                _("Invalid perms in topic rule '%s'") % raw_rule)

        return TopicRule(path, perms,
                         audit=audit, deny=deny, allow_keyword=allow_keyword, comment=comment)

    def get_clean(self, depth=0):
        '''return rule (in clean/default formatting)'''

        space = '  ' * depth

        if self.all_paths:
            path = ''
        elif self.path:
            path = quote_if_needed(self.path.regex)
        else:
            raise ComArmorBug('Empty path in topic rule')

        if self.all_perms:
            perms = ''
        else:
            perms = self._joint_perms()
            if not perms:
                raise ComArmorBug('Empty permissions in topic rule')

        path_and_perms = '%s %s' % (path, perms)

        topic_keyword = 'topic '

        if not self.all_paths and not self.all_perms and path and perms:
            return('%s%s%s%s,%s' % (space, self.modifiers_str(), topic_keyword,
                                    path_and_perms, self.comment))
        else:
            raise ComArmorBug(
                'Invalid combination of path and perms in topic rule - specify path and perms')

    def _joint_perms(self):
        '''return the permissions as string (using self.perms)'''
        return self._join_given_perms(self.perms)  # TODO Remove?

    def _join_given_perms(self, perms):
        '''return the permissions as string (using the perms given as parameter)'''
        perm_string = ''
        for perm in topic_permissions:
            if perm in perms:
                perm_string = perm_string + perm

        return perm_string

    def is_covered_localvars(self, other_rule):
        '''check if other_rule is covered by this rule object'''

        if not self._is_covered_aare(self.path,  self.all_paths,
                                     other_rule.path, other_rule.all_paths, 'path'):
            return False

        if not self._is_covered_list(self.perms, self.all_perms,
                                     other_rule.perms, other_rule.all_perms, 'perms'):
            return False

        # still here? -> then it is covered
        return True

    def is_equal_localvars(self, rule_obj, strict):
        '''compare if rule-specific variables are equal'''

        if not type(rule_obj) == TopicRule:
            raise ComArmorBug('Passed non-topic rule: %s' % str(rule_obj))

        if not self._is_equal_aare(self.path, self.all_paths,
                                   rule_obj.path, rule_obj.all_paths, 'path'):
            return False

        if self.perms != rule_obj.perms:
            return False

        if self.all_perms != rule_obj.all_perms:
            return False

        return True

    def severity(self, sev_db):
        if self.all_paths:
            severity = sev_db.rank_path('/**', 'spr')
        else:
            severity = -1
            sev = sev_db.rank_path(self.path.regex, self._joint_perms())
            if isinstance(sev, int):  # type check avoids breakage caused by 'unknown'
                severity = max(severity, sev)

        if severity == -1:
            severity = sev  # effectively 'unknown'

        return severity

    def logprof_header_localvars(self):
        headers = []

        path = logprof_value_or_all(self.path, self.all_paths)
        headers += [_('Path'), path]

        old_mode = ''
        if self.original_perms:
            original_perms_all = self._join_given_perms(
                self.original_perms['allow'], None)

            if original_perms_all:
                old_mode = original_perms_all
            else:
                old_mode = ''

        if old_mode:
            headers += [_('Old Mode'), old_mode]

        perms = logprof_value_or_all(self.perms, self.all_perms)
        if self.perms:
            perms = self._joint_perms()

        headers += [_('New Mode'), perms]

        # topic_keyword and leading_perms are not really relevant
        return headers

    def glob(self):
        '''Change path to next possible glob'''
        if self.all_paths:
            return

        self.path = self.path.glob_path()
        self.raw_rule = None

    def glob_ext(self):
        '''Change path to next possible glob with extension'''
        if self.all_paths:
            return

        self.path = self.path.glob_path_withext()
        self.raw_rule = None

    def edit_header(self):
        if self.all_paths:
            raise ComArmorBug('Attemp to edit bare topic rule')

        return(_('Enter new path: '), self.path.regex)

    def validate_edit(self, newpath):
        if self.all_paths:
            raise ComArmorBug('Attemp to edit bare topic rule')

        # might raise ComArmorException if the new path doesn't start with / or a variable
        newpath = AARE(newpath, True)
        return newpath.match(self.path)

    def store_edit(self, newpath):
        if self.all_paths:
            raise ComArmorBug('Attemp to edit bare topic rule')

        # might raise ComArmorException if the new path doesn't start with / or a variable
        self.path = AARE(newpath, True)
        self.raw_rule = None


class TopicRuleset(BaseRuleset):
    '''Class to handle and store a collection of topic rules'''

    def get_rules_for_path(self, path, audit=False, deny=False):
        '''Get all rules matching the given path
           path can be str or AARE
           If audit is True, only return rules with the audit flag set.
           If deny is True, only return matching deny rules'''

        matching_rules = TopicRuleset()
        for rule in self.rules:
            if ((rule.all_paths or rule.path.match(path)) and
                    ((not deny) or rule.deny) and
                    ((not audit) or rule.audit)):
                matching_rules.add(rule)

        return matching_rules

    def get_perms_for_path(self, path, audit=False, deny=False):
        '''Get the summarized permissions of all rules matching the given path,
           and the list of paths involved in the calculation path can be str or AARE
           If audit is True, only analyze rules with the audit flag set.
           If deny is True, only analyze matching deny rules
           Returns {'allow': set_of_perms,
                    'deny':  set_of_perms,
                    'path':  involved_paths}
           '''

        perms = {
            'allow':    set(),
            'deny':     set(),
        }
        all_perms = {
            'allow':    False,
            'deny':     False,
        }
        paths = set()

        matching_rules = self.get_rules_for_path(path, audit, deny)

        for rule in matching_rules.rules:
            allow_or_deny = 'allow'
            if rule.deny:
                allow_or_deny = 'deny'

            if rule.all_perms:
                all_perms[allow_or_deny] = True
            elif rule.perms:
                perms[allow_or_deny] = perms[allow_or_deny].union(rule.perms)
                paths.add(rule.path.regex)

        allow = None
        deny = None
        if all_perms['allow']:
            allow = TopicRule.ALL
        else:
            allow = perms['allow']

        if all_perms['deny']:
            deny = TopicRule.ALL
        else:
            deny = perms['deny']

        return {'allow': allow, 'deny': deny, 'paths': paths}


def split_perms(perm_string, deny):
    '''parse permission string
       - perm_string: the permission string to parse
       - deny: True if this is a deny rule
   '''
    perms = set()
    exec_mode = None

    while perm_string:
        if perm_string[0] in topic_permissions:
            perms.add(perm_string[0])
            perm_string = perm_string[1:]
        else:
            raise ComArmorException(
                _('permission contains unknown character(s) %s' % perm_string))

    return perms, exec_mode

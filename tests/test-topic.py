#!/usr/bin/python3
# ----------------------------------------------------------------------
#    Copyright (C) 2015 Christian Boltz <apparmor@cboltz.de>
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

import os
import unittest

from collections import namedtuple
from common import CATest, setup_all_loops

from comarmor.rule.topic import TopicRule, TopicRuleset
from comarmor.rule import BaseRule
import comarmor.severity as severity
from apparmor.common import AppArmorException, AppArmorBug
from comarmor.common import ComArmorException, ComArmorBug
# from apparmor.logparser import ReadLog
from apparmor.translations import init_translation
_ = init_translation()

PWD = os.path.dirname(os.path.realpath(__file__))

exp = namedtuple('exp', ['audit', 'allow_keyword', 'deny', 'comment',
        'path', 'all_paths', 'perms', 'all_perms'])

# --- tests for single TopicRule --- #

class TopicTest(CATest):
    def _compare_obj(self, obj, expected):
        self.assertEqual(obj.allow_keyword, expected.allow_keyword)
        self.assertEqual(obj.audit, expected.audit)
        self.assertEqual(obj.deny, expected.deny)
        self.assertEqual(obj.comment, expected.comment)

        self._assertEqual_aare(obj.path, expected.path)
        self.assertEqual(obj.perms, expected.perms)

        self.assertEqual(obj.all_paths, expected.all_paths)
        self.assertEqual(obj.all_perms, expected.all_perms)

    def _assertEqual_aare(self, obj, expected):
        if obj:
            self.assertEqual(obj.regex, expected)
        else:
            self.assertEqual(obj, expected)

class TopicTestParse(TopicTest):
    tests = [
        # TopicRule object                             audit  allow  deny   comment    path                  all_paths?  perms              all_perms?

        # "normal" topic rules
        ('topic /foo r,'                         , exp(False, False, False, '',        '/foo',               False,      {'r'},             False,  )),
        ('topic /foo spr,'                       , exp(False, False, False, '',        '/foo',               False,      {'s', 'p', 'r'},   False,  )),
        ('topic @{PROC}/[a-z]** sp,'             , exp(False, False, False, '',        '@{PROC}/[a-z]**',    False,      {'s', 'p'},        False,  )),

        ('audit topic /tmp/foo r,'               , exp(True,  False, False, '',        '/tmp/foo',           False,      {'r'},             False,  )),
        ('audit deny topic /tmp/foo r,'          , exp(True,  False, True,  '',        '/tmp/foo',           False,      {'r'},             False,  )),
        ('audit deny topic /tmp/foo sr,'         , exp(True,  False, True,  '',        '/tmp/foo',           False,      {'s', 'r'},        False,  )),
        ('allow topic /tmp/foo rs,'              , exp(False, True,  False, '',        '/tmp/foo',           False,      {'r', 's'},        False,  )),
        ('audit allow topic /tmp/foo rs,'        , exp(True,  True,  False, '',        '/tmp/foo',           False,      {'r', 's'},        False,  )),

        # "normal" topic rules with comment
        ('topic /foo r, # cmt'                   , exp(False, False, False, ' # cmt',  '/foo',               False,      {'r'},             False,  )),
    ]

    def _run_test(self, rawrule, expected):
        self.assertTrue(TopicRule.match(rawrule))
        obj = TopicRule.parse(rawrule)
        self.assertEqual(rawrule.strip(), obj.raw_rule)
        self._compare_obj(obj, expected)

class TopicTestNonMatch(CATest):
    tests = [
        ('topic,'            , False ), # is bare
        ('topic /foo,'       , False ), # missing perm
        ('topic sp,'         , False ), # missing path
        ('topic sp /foo,'    , False ), # out of order path and perm
        ('/foo sp,'          , False ), # missing keyword
        ('service /foo sp,'  , False ), # wrong keyword
    ]

    def _run_test(self, rawrule, expected):
        self.assertFalse(TopicRule.match(rawrule))

# class TopicTestParseFromLog(TopicTest):
#     def test_file_from_log(self):
#         parser = ReadLog('', '', '', '')
#         event = 'Nov 11 07:33:07 myhost kernel: [50812.879558] type=1502 audit(1236774787.169:369): operation="inode_permission" requested_mask="::r" denied_mask="::r" fsuid=1000 name="/bin/dash" pid=13726 profile="/bin/foobar"'
#
#         parsed_event = parser.parse_event(event)
#
#         self.assertEqual(parsed_event, {
#             'request_mask': '::r',
#             'denied_mask': '::r',
#             'error_code': 0,
#             'magic_token': 0,
#             'parent': 0,
#             'profile': '/bin/foobar',
#             'operation': 'inode_permission',
#             'name': '/bin/dash',
#             'name2': None,
#             'resource': None,
#             'info': None,
#             'aamode': 'PERMITTING',
#             'time': 1236774787,
#             'active_hat': None,
#             'pid': 13726,
#             'task': 0,
#             'attr': None,
#             'family': None,
#             'protocol': None,
#             'sock_type': None,
#         })
#
#         #TopicRule#     path,                 perms,                         exec_perms, target,         owner,  file_keyword,   leading_perms
#         #obj = TopicRule(parsed_event['name'], parsed_event['denied_mask'],   None,       TopicRule.ALL,   False,  False,          False,         )
#         obj = TopicRule(parsed_event['name'], 'r',                           None,       FileRule.ALL,   False,  False,          False,         )
#         # XXX handle things like '::r'
#         # XXX split off exec perms?
#
#         #              audit  allow  deny   comment    path              all_paths   perms           all?    exec_perms  target      all?    owner   file keyword    leading perms
#         expected = exp(False, False, False, '',        '/bin/dash',      False,      {'r'},          False,  None,       None,       True,   False,  False,          False       )
#
#         self._compare_obj(obj, expected)
#
#         self.assertEqual(obj.get_raw(1), '  /bin/dash r,')

class TopicFromInit(TopicTest):
    tests = [

        #TopicRule# path,           perms,
        (TopicRule( '/foo',         'ps',   audit=True,     deny=True   ),
                    #exp#   audit   allow   deny    comment     path            all_paths?  perms           all_perms?
                    exp(    True,   False,  True,   '',         '/foo',         False,      {'p', 's'},     False     )),

        #TopicRule# path,           perms,  audit   deny            allow_keyword           comment='',     log_event=None
        (TopicRule( '/foo',         'r',    False,  False,          allow_keyword=True,     comment=' # bar'    ),
                    #exp#   audit   allow   deny    comment     path            all_paths?  perms           all_perms?
                    exp(    False,  True,   False,  ' # bar',   '/foo',         False,      {'r'},          False,    )),

    ]

    def _run_test(self, obj, expected):
        self._compare_obj(obj, expected)

class InvalidTopicInit(CATest):
    tests = [
        #TopicRule#  path,           perms

        # empty fields
        (        (  '',             'spr',   ), AppArmorBug),
        (        (  '/foo',         '',      ), ComArmorBug),

        # whitespace fields
        (        (  '   ',          'spr',   ), AppArmorBug),
        (        (  '/foo',         '   ',   ), ComArmorException),

        # wrong type - dict()
        (        (  dict(),         'spr',   ), AppArmorBug),
        (        (  '/foo',         dict(),  ), ComArmorBug),


        # wrong type - None
        (        (  None,           'spr',   ), AppArmorBug),
        (        (  '/foo',         None,    ), ComArmorBug),


        # misc
        (        (  'foo',          'spr',   ), AppArmorException),   # path doesn't start with /
        (        (  '/foo',         'rb',    ), ComArmorException),   # invalid file mode 'b' (str)
        (        (  '/foo',         {'b'},   ), ComArmorBug),         # invalid file mode 'b' (str)
        (        (  TopicRule.ALL,   TopicRule.ALL  ), ComArmorBug),  # plain 'topic,' not allowed
    ]

    def _run_test(self, params, expected):
        with self.assertRaises(expected):
            TopicRule(params[0], params[1])

    def test_missing_params_0(self):
        with self.assertRaises(TypeError):
            TopicRule()

    def test_missing_params_1(self):
        with self.assertRaises(TypeError):
            TopicRule('/foo')

class InvalidTopicTest(CATest):
    def _check_invalid_rawrule(self, rawrule):
        obj = None
        self.assertFalse(TopicRule.match(rawrule))
        with self.assertRaises(ComArmorException):
            obj = TopicRule(TopicRule.parse(rawrule))

        self.assertIsNone(obj, 'TopicRule handed back an object unexpectedly')

    def test_invalid_topic_missing_comma_1(self):
        self._check_invalid_rawrule('topic')  # missing comma

    def test_invalid_non_TopicRule(self):
        self._check_invalid_rawrule('signal,')  # not a topic rule

class BrokenTopicTest(CATest):
    def CASetup(self):
        #TopicRule#          path,           perms
        self.obj = TopicRule('/foo',         'psr')

    def test_empty_data_1(self):
        self.obj.path = ''
        # no path set, and ALL not set
        with self.assertRaises(ComArmorBug):
            self.obj.get_clean(1)

    def test_empty_data_2(self):
        self.obj.perms = ''
        # no perms set, and ALL not set
        with self.assertRaises(ComArmorBug):
            self.obj.get_clean(1)

    def test_unexpected_all_1(self):
        self.obj.all_paths = TopicRule.ALL
        # all_paths and all_perms must be in sync
        with self.assertRaises(ComArmorBug):
            self.obj.get_clean(1)

    def test_unexpected_all_2(self):
        self.obj.all_perms = TopicRule.ALL
        # all_paths and all_perms must be in sync
        with self.assertRaises(ComArmorBug):
            self.obj.get_clean(1)

class TopicGlobTest(CATest):
    def _run_test(self, params, expected):
        exp_can_glob, exp_can_glob_ext, exp_rule_glob, exp_rule_glob_ext = expected

        # test glob()
        rule_obj = TopicRule.parse(params)
        self.assertEqual(exp_can_glob, rule_obj.can_glob)
        self.assertEqual(exp_can_glob_ext, rule_obj.can_glob_ext)

        rule_obj.glob()
        self.assertEqual(rule_obj.get_clean(), exp_rule_glob)

        # test glob_ext()
        rule_obj = TopicRule.parse(params)
        self.assertEqual(exp_can_glob, rule_obj.can_glob)
        self.assertEqual(exp_can_glob_ext, rule_obj.can_glob_ext)

        rule_obj.glob_ext()
        self.assertEqual(rule_obj.get_clean(), exp_rule_glob_ext)

    # These tests are meant to ensure AARE integration in TopicRule works as expected.
    # test-aare.py has more comprehensive globbing tests.
    tests = [
        # rule                      can glob   can glob_ext    globbed rule        globbed_ext rule
        ('topic /foo/bar r,',     (True,      True,           'topic /foo/* r,',   'topic /foo/bar r,')),
        ('topic /foo/* r,',       (True,      True,           'topic /** r,',      'topic /foo/* r,')),
        ('topic /foo/bar.xy r,',  (True,      True,           'topic /foo/* r,',   'topic /foo/*.xy r,')),
        ('topic /foo/*.xy r,',    (True,      True,           'topic /foo/* r,',   'topic /**.xy r,')),
        # ('topic,',           (False,     False,          'topic,',            'topic,')),  # bare 'topic,' rules can't be globbed
    ]

class WriteTopicTest(CATest):
    def _run_test(self, rawrule, expected):
       self.assertTrue(TopicRule.match(rawrule), 'TopicRule.match() failed')
       obj = TopicRule.parse(rawrule)
       clean = obj.get_clean()
       raw = obj.get_raw()

       self.assertEqual(expected.strip(), clean, 'unexpected clean rule')
       self.assertEqual(rawrule.strip(), raw, 'unexpected raw rule')

    tests = [
        #  raw rule                                                           clean rule
        # ('topic,'                                                            , 'topic,'),
        # ('              topic        ,  # foo        '                       , 'topic, # foo'),
        ('    audit     topic /foo r,'                                       , 'audit topic /foo r,'),
        ('    audit     topic /foo  rsp,'                                    , 'audit topic /foo psr,'),  # re-order perms by topic_permissions array
        ('    deny      topic /foo r,'                                       , 'deny topic /foo r,'),
        ('    deny      topic /foo  sp,'                                     , 'deny topic /foo ps,'),
        ('    allow      topic /foo r,'                                      , 'allow topic /foo r,'),
        ('    allow      topic /foo  sp,'                                    , 'allow topic /foo ps,'),
        ('    audit   deny      topic /foo r,'                               , 'audit deny topic /foo r,'),
        ('    audit   deny      topic /foo  sp,'                             , 'audit deny topic /foo ps,'),
        ('    audit   allow      topic /foo r,'                              , 'audit allow topic /foo r,'),
        ('    audit   allow      topic /foo  sp,'                            , 'audit allow topic /foo ps,'),
  ]

    def test_write_manually_1(self):
       #TopicRule#      path,           perms
       obj = TopicRule( '/foo',         'sp',  allow_keyword=True)

       expected = '    allow topic /foo ps,'

       self.assertEqual(expected, obj.get_clean(2), 'unexpected clean rule')
       self.assertEqual(expected, obj.get_raw(2), 'unexpected raw rule')

    def test_write_manually_2(self):
       #TopicRule#      path,           perms
       obj = TopicRule( '/foo',         'rp',  deny=True)

       expected = '    deny topic /foo pr,'

       self.assertEqual(expected, obj.get_clean(2), 'unexpected clean rule')
       self.assertEqual(expected, obj.get_raw(2), 'unexpected raw rule')

class TopicCoveredTest(CATest):
    def _run_test(self, param, expected):
        obj = TopicRule.parse(self.rule)
        check_obj = TopicRule.parse(param)

        self.assertTrue(TopicRule.match(param))

        self.assertEqual(obj.is_equal(check_obj), expected[0], 'Mismatch in is_equal, expected %s' % expected[0])
        self.assertEqual(obj.is_equal(check_obj, True), expected[1], 'Mismatch in is_equal/strict, expected %s' % expected[1])

        self.assertEqual(obj.is_covered(check_obj), expected[2], 'Mismatch in is_covered, expected %s' % expected[2])
        self.assertEqual(obj.is_covered(check_obj, True, True), expected[3], 'Mismatch in is_covered/exact, expected %s' % expected[3])

class TopicCoveredTest_01(TopicCoveredTest):
    rule = 'topic /foo r,'

    tests = [
        #   rule                                            equal     strict equal    covered     covered exact
        ('topic /foo r,'                                 , [ True    , True          , True      , True      ]),
        ('topic /foo r ,'                                , [ True    , False         , True      , True      ]),
        ('allow topic /foo r,'                           , [ True    , False         , True      , True      ]),
        ('allow topic /foo r, # comment'                 , [ True    , False         , True      , True      ]),
        # ('topic,'                                        , [ False   , False         , False     , False     ]),
        ('topic /foo p,'                                 , [ False   , False         , False     , False     ]),
        ('topic /foo rp,'                                , [ False   , False         , False     , False     ]),
        ('topic /bar r,'                                 , [ False   , False         , False     , False     ]),
        ('audit topic /foo r,'                           , [ False   , False         , False     , False     ]),
        # ('audit topic,'                                  , [ False   , False         , False     , False     ]),
        ('audit deny topic /foo r,'                      , [ False   , False         , False     , False     ]),
        ('deny topic /foo r,'                            , [ False   , False         , False     , False     ]),
    ]

class TopicCoveredTest_02(TopicCoveredTest):
    rule = 'audit topic /foo r,'

    tests = [
        #   rule                                            equal     strict equal    covered     covered exact
        ('topic /foo r,'                                 , [ False   , False         , True      , False     ]),
        ('allow topic /foo r,'                           , [ False   , False         , True      , False     ]),
        ('allow topic /foo r, # comment'                 , [ False   , False         , True      , False     ]),
        # # ('topic,'                                        , [ False   , False         , False     , False     ]),
        ('topic /foo p,'                                 , [ False   , False         , False     , False     ]),
        ('topic /foo rp,'                                , [ False   , False         , False     , False     ]),
        ('topic /bar r,'                                 , [ False   , False         , False     , False     ]),
        ('audit topic /foo r,'                           , [ True    , True          , True      , True      ]),
        # ('audit topic,'                                  , [ False   , False         , False     , False     ]),
        ('audit deny topic /foo r,'                      , [ False   , False         , False     , False     ]),
        ('deny topic /foo r,'                            , [ False   , False         , False     , False     ]),
    ]

class TopicCoveredTest_03(TopicCoveredTest):
    rule = 'topic /foo spr,'

    tests = [
        #   rule                                            equal     strict equal    covered     covered exact
        ('topic /foo r,'                                 , [ False   , False         , True      , True      ]),
        ('allow topic /foo r,'                           , [ False   , False         , True      , True      ]),
        ('allow topic /foo r, # comment'                 , [ False   , False         , True      , True      ]),
        # ('topic,'                                        , [ False   , False         , False     , False     ]),
        ('topic /foo p,'                                 , [ False   , False         , True      , True      ]),
        ('topic /foo rp,'                                , [ False   , False         , True      , True      ]),
        ('topic /bar r,'                                 , [ False   , False         , False     , False     ]),
        ('audit topic /foo r,'                           , [ False   , False         , False     , False     ]),
        # ('audit topic,'                                  , [ False   , False         , False     , False     ]),
        ('audit deny topic /foo r,'                      , [ False   , False         , False     , False     ]),
        ('deny topic /foo r,'                            , [ False   , False         , False     , False     ]),
        ('topic /foo spr,'                               , [ True    , True          , True      , True      ]),
        ('topic /foo rps,'                               , [ True    , False         , True      , True      ]),
    ]

# class TopicCoveredTest_05(TopicCoveredTest):
#     rule = 'topic,'
#
#     tests = [
#         #   rule                                            equal     strict equal    covered     covered exact
#         ('topic /foo r,'                                 , [ False   , False         , True      , True      ]),
#         ('allow topic /foo r,'                           , [ False   , False         , True      , True      ]),
#         ('allow /foo r, # comment'                      , [ False   , False         , True      , True      ]),
#         ('allow owner /foo r,'                          , [ False   , False         , True      , True      ]),
#         ('/foo r -> bar,'                               , [ False   , False         , True      , True      ]),
#         ('topic r /foo,'                                 , [ False   , False         , True      , True      ]),
#         ('allow topic r /foo,'                           , [ False   , False         , True      , True      ]),
#         ('allow r /foo, # comment'                      , [ False   , False         , True      , True      ]),
#         ('allow owner r /foo,'                          , [ False   , False         , True      , True      ]),
#         ('r /foo -> bar,'                               , [ False   , False         , True      , True      ]),
#         ('topic,'                                        , [ True    , True          , True      , True      ]),
#         ('topic /foo w,'                                 , [ False   , False         , True      , True      ]),
#         ('topic /foo rw,'                                , [ False   , False         , True      , True      ]),
#         ('topic /bar r,'                                 , [ False   , False         , True      , True      ]),
#         ('audit /foo r,'                                , [ False   , False         , False     , False     ]),
#         ('audit topic,'                                  , [ False   , False         , False     , False     ]),
#         ('audit deny /foo r,'                           , [ False   , False         , False     , False     ]),
#         ('deny topic /foo r,'                            , [ False   , False         , False     , False     ]),
#         ('/foo mrwPx,'                                  , [ False   , False         , False     , False     ]),
#         ('/foo wPxrm,'                                  , [ False   , False         , False     , False     ]),
#         ('/foo rm,'                                     , [ False   , False         , True      , True      ]),
#         ('/foo Px,'                                     , [ False   , False         , False     , False     ]),
#         ('/foo ix,'                                     , [ False   , False         , False     , False     ]),
#         ('/foo ix -> bar,'                              , [ False   , False         , False     , False     ]),
#         ('/foo mrwPx -> bar,'                           , [ False   , False         , False     , False     ]),
#     ]

class TopicCoveredTest_ManualOrInvalid(CATest):
    def CASetup(self):
        #TopicRule#                 path,           perms,  exec_perms, target,         owner,  topic_keyword,   leading_perms
        self.obj       = TopicRule( '/foo',         'rp')  #,   'ix',       '/bar',         False,  False,          False)
        self.testobj   = TopicRule( '/foo',         'rp')  #,   'ix',       '/bar',         False,  False,          False)

    def test_equal_all_perms(self):
        self.testobj.all_perms = True  # that makes testobj invalid, but that's the only way to survive the 'perms' comparison
        self.assertFalse(self.obj.is_equal(self.testobj))

    def test_covered_anyperm_1(self):
        self.obj       = TopicRule( '/foo',         'rp')
        self.testobj   = TopicRule( '/foo',         'rs')
        self.assertFalse(self.obj.is_covered(self.testobj))
        self.assertFalse(self.obj.is_equal(self.testobj, strict=False))
        self.assertFalse(self.obj.is_equal(self.testobj, strict=True))

    def test_covered_anyperm_2(self):
        self.testobj   = TopicRule( '/foo',         'r')
        self.assertTrue(self.obj.is_covered(self.testobj))
        self.assertFalse(self.obj.is_equal(self.testobj, strict=False))
        self.assertFalse(self.obj.is_equal(self.testobj, strict=True))

    def test_covered_anyperm_3(self):
        self.obj       = TopicRule( '/foo',         'rp', deny=True)
        self.testobj   = TopicRule( '/foo',         'rp')
        self.assertFalse(self.obj.is_covered(self.testobj))
        self.assertTrue(self.obj.is_covered(self.testobj, check_allow_deny=False))
        self.assertFalse(self.obj.is_equal(self.testobj, strict=False))
        self.assertFalse(self.obj.is_equal(self.testobj, strict=True))

    def test_borked_obj_is_covered_1(self):
        self.testobj.path = ''

        with self.assertRaises(AppArmorBug):
            self.obj.is_covered(self.testobj)

    def test_borked_obj_is_covered_2(self):
        self.testobj.perms = set()

        with self.assertRaises(AppArmorBug):
            self.obj.is_covered(self.testobj)

    def test_invalid_is_covered(self):
        obj = TopicRule.parse('topic /foo rp,')

        testobj = BaseRule()  # different type

        with self.assertRaises(AppArmorBug):
            obj.is_covered(testobj)

    def test_invalid_is_equal(self):
        obj = TopicRule.parse('topic /foo rp,')

        testobj = BaseRule()  # different type

        with self.assertRaises(ComArmorBug):
            obj.is_equal(testobj)

class TopicSeverityTest(CATest):
    tests = [
        ('topic /tf_static p,',             8),
        ('topic /spam rp,',                 'unknown'),
        ('topic /rosout* r,',               0),
        ('topic /goal_foo rps,',            7),
        ('topic /goal/foo rps,',            6),
        ('topic /e_stop ps,',               10),
        ('topic /bot_joy r,',               6),
        ('topic /etc/** r,',                'unknown'),
        ('topic /bar/foo@pop/@pop r,',      'unknown'),  # topicname containing @
        ('topic /baz/foo@pop r,',           1),  # topicname containing @
    ]

    def _run_test(self, params, expected):
        sev_db = severity.TopicSeverity(os.path.join(PWD, 'data/topic-severity.db'), 'unknown')
        obj = TopicRule.parse(params)
        rank = obj.severity(sev_db)
        self.assertEqual(rank, expected)

class TopicLogprofHeaderTest(CATest):
    tests = [
        # log event                        old perms ALL / owner
        # (['topic,',                              set(),      ], [                               _('Path'), _('ALL'),                                         _('New Mode'), _('ALL')                 ]),
        (['topic /foo r,',                       set(),      ], [                               _('Path'), '/foo',                                           _('New Mode'), 'r'                      ]),
        (['deny topic /foo r,',                  set(),      ], [_('Qualifier'), 'deny',        _('Path'), '/foo',                                           _('New Mode'), 'r'                      ]),
        (['allow topic /baz psr,',               set(),      ], [_('Qualifier'), 'allow',       _('Path'), '/baz',                                           _('New Mode'), 'psr'                    ]),
        (['audit topic /foo pr,',                set(),      ], [_('Qualifier'), 'audit',       _('Path'), '/foo',                                           _('New Mode'), 'pr'                     ]),
        (['audit deny topic /foo ps,',           set(),      ], [_('Qualifier'), 'audit deny',  _('Path'), '/foo',                                           _('New Mode'), 'ps'                     ]),
        (['topic /foo ps,',                      set('s'),   ], [                               _('Path'), '/foo',         _('Old Mode'), _('s'),            _('New Mode'), _('ps')                 ]),
   ]

    def _run_test(self, params, expected):
        obj = TopicRule._parse(params[0])
        if params[1]:
            obj.original_perms = {'allow': params[1]}
        self.assertEqual(obj.logprof_header(), expected)

    def test_empty_original_perms(self):
        obj = TopicRule._parse('topic /foo pr,')
        obj.original_perms = {'allow': set()}
        self.assertEqual(obj.logprof_header(), [_('Path'), '/foo', _('New Mode'), _('pr')])

class TopicEditHeaderTest(CATest):
    def _run_test(self, params, expected):
        rule_obj = TopicRule.parse(params)
        self.assertEqual(rule_obj.can_edit, True)
        prompt, path_to_edit = rule_obj.edit_header()
        self.assertEqual(path_to_edit, expected)

    tests = [
        ('topic /foo/bar/baz r,',         '/foo/bar/baz'),
        ('topic /foo/**/baz r,',          '/foo/**/baz'),
    ]

    # def test_edit_header_bare_topic(self):
    #     rule_obj = TopicRule.parse('topic,')
    #     self.assertEqual(rule_obj.can_edit, False)
    #     with self.assertRaises(ComArmorBug):
    #         rule_obj.edit_header()

class TopicValidateAndStoreEditTest(CATest):
    def _run_test(self, params, expected):
        rule_obj = TopicRule('/foo/bar/baz', 'r', False, log_event=True)

        self.assertEqual(rule_obj.validate_edit(params), expected)

        rule_obj.store_edit(params)
        self.assertEqual(rule_obj.get_raw(), 'topic %s r,' % params)

    tests = [
        # edited path           match
        ('/foo/bar/baz',        True),
        ('/foo/bar/*',          True),
        ('/foo/bar/???',        True),
        ('/foo/xy**',           False),
        ('/foo/bar/baz/',       False),
    ]

    def test_validate_not_a_path(self):
        rule_obj = TopicRule.parse('topic /foo/bar/baz r,')

        with self.assertRaises(AppArmorException):
            rule_obj.validate_edit('foo/bar/baz')

        with self.assertRaises(AppArmorException):
            rule_obj.store_edit('foo/bar/baz')

    # def test_validate_edit_bare_topic(self):
    #     rule_obj = TopicRule.parse('topic,')
    #     self.assertEqual(rule_obj.can_edit, False)
    #
    #     with self.assertRaises(AppArmorBug):
    #         rule_obj.validate_edit('/foo/bar')
    #
    #     with self.assertRaises(AppArmorBug):
    #         rule_obj.store_edit('/foo/bar')



## --- tests for TopicRuleset --- #

class TopicRulesTest(CATest):
    def test_empty_ruleset(self):
        ruleset = TopicRuleset()
        ruleset_2 = TopicRuleset()
        self.assertEqual([], ruleset.get_raw(2))
        self.assertEqual([], ruleset.get_clean(2))
        self.assertEqual([], ruleset_2.get_raw(2))
        self.assertEqual([], ruleset_2.get_clean(2))

    def test_ruleset_1(self):
        ruleset = TopicRuleset()
        rules = [
            '   topic /foo rp,',
            '  topic /bar r,',
        ]

        expected_raw = [
            'topic /foo rp,',
            'topic /bar r,',
            '',
        ]

        expected_clean = [
            'topic /bar r,',
            'topic /foo pr,',
            '',
        ]

        deleted = 0
        for rule in rules:
            deleted += ruleset.add(TopicRule.parse(rule))

        self.assertEqual(deleted, 0)
        self.assertEqual(expected_raw, ruleset.get_raw())
        self.assertEqual(expected_clean, ruleset.get_clean())

    def test_ruleset_cleanup_add_1(self):
        ruleset = TopicRuleset()
        rules = [
            'topic /foo/bar r,',
            'topic /foo/baz rp,',
            'topic /foo/baz rps,',
        ]

        rules_with_cleanup = [
            'topic /foo/* r,',
        ]

        expected_raw = [
            '  topic /foo/baz rp,',
            '  topic /foo/baz rps,',
            '  topic /foo/* r,',
             '',
        ]

        expected_clean = [
            '  topic /foo/* r,',
            '  topic /foo/baz pr,',
            '  topic /foo/baz psr,',
             '',
        ]

        deleted = 0
        for rule in rules:
            deleted += ruleset.add(TopicRule.parse(rule))

        self.assertEqual(deleted, 0)  # rules[] are added without cleanup mode, so the superfluous '/foo/baz rp,' should be kept

        for rule in rules_with_cleanup:
            deleted += ruleset.add(TopicRule.parse(rule), cleanup=True)

        self.assertEqual(deleted, 1)  # rules_with_cleanup made 'topic /foo/bar r,' superfluous
        self.assertEqual(expected_raw, ruleset.get_raw(1))
        self.assertEqual(expected_clean, ruleset.get_clean(1))


#class TopicDeleteTest(CATest):
#    pass

class TopicGetRulesForPath(CATest):
    tests = [
        #  path                                 audit   deny    expected
        (('/etc/foo/dovecot.conf',              False,  False), ['topic /etc/foo/* r,', 'topic /etc/foo/dovecot.conf pr,',                                  '']),
        (('/etc/foo/foo.conf',                  False,  False), ['topic /etc/foo/* r,',                                                                     '']),
        (('/etc/foo/dovecot-database.conf.ext', False,  False), ['topic /etc/foo/* r,', 'topic /etc/foo/dovecot-database.conf.ext p,',                      '']),
        (('/etc/foo/auth.d/authfoo.conf',       False,  False), ['topic /etc/foo/{auth,conf}.d/*.conf r,','topic /etc/foo/{auth,conf}.d/authfoo.conf p,',   '']),
        (('/etc/foo/dovecot-deny.conf',         False,  False), ['deny topic /etc/foo/dovecot-deny.conf r,', '', 'topic /etc/foo/* r,',                     '']),
        (('/foo/bar',                           False,  True ), [                                                                                             ]),
        (('/etc/foo/dovecot-deny.conf',         False,  True ), ['deny topic /etc/foo/dovecot-deny.conf r,',                                                '']),
        (('/etc/foo/foo.conf',                  False,  True ), [                                                                                             ]),
    ]

    def _run_test(self, params, expected):
        rules = [
            'topic /etc/foo/* r,',
            'topic /etc/foo/dovecot.conf rp,',
            'topic /etc/foo/{auth,conf}.d/*.conf r,',
            'topic /etc/foo/{auth,conf}.d/authfoo.conf p,',
            'topic /etc/foo/dovecot-database.conf.ext p,',
            'deny topic /etc/foo/dovecot-deny.conf r,',
        ]

        ruleset = TopicRuleset()
        for rule in rules:
            ruleset.add(TopicRule.parse(rule))

        matching = ruleset.get_rules_for_path(params[0], params[1], params[2])
        self. assertEqual(matching.get_clean(), expected)


class TopicGetPermsForPath_1(CATest):
    tests = [
        #  path                                 audit   deny    expected
        (('/etc/foo/dovecot.conf',              False,  False), {'allow': {'r', 'p'},  'deny': set(),   'paths': {'/etc/foo/*', '/etc/foo/dovecot.conf'                                    }   }),
        (('/etc/foo/foo.conf',                  False,  False), {'allow': {'r'     },  'deny': set(),   'paths': {'/etc/foo/*'                                                             }   }),
        (('/etc/foo/dovecot-database.conf.ext', False,  False), {'allow': {'r', 'p'},  'deny': set(),   'paths': {'/etc/foo/*', '/etc/foo/dovecot-database.conf.ext'                       }   }),
        (('/etc/foo/auth.d/authfoo.conf',       False,  False), {'allow': {'r', 'p'},  'deny': set(),   'paths': {'/etc/foo/{auth,conf}.d/*.conf', '/etc/foo/{auth,conf}.d/authfoo.conf'   }   }),
        (('/etc/foo/dovecot-deny.conf',         False,  False), {'allow': {'r'     },  'deny': {'r'},   'paths': {'/etc/foo/*', '/etc/foo/dovecot-deny.conf'                               }   }),
        (('/foo/bar',                           False,  True ), {'allow': set()     ,  'deny': set(),   'paths': set()                                                                         }),
        (('/etc/foo/dovecot-deny.conf',         False,  True ), {'allow': set()     ,  'deny': {'r'},   'paths': {'/etc/foo/dovecot-deny.conf'                                             }   }),
        (('/etc/foo/foo.conf',                  False,  True ), {'allow': set()     ,  'deny': set(),   'paths': set()                                                                         }),
        (('/usr/lib/dovecot/config',            False,  False), {'allow': {'s'}     ,  'deny': set(),   'paths': {'/usr/lib/dovecot/config'}                                                   }),
    ]

    def _run_test(self, params, expected):
        rules = [
            'topic /etc/foo/* r,',
            'topic /etc/foo/dovecot.conf rp,',
            'topic /etc/foo/{auth,conf}.d/*.conf r,',
            'topic /etc/foo/{auth,conf}.d/authfoo.conf p,',
            'topic /etc/foo/dovecot-database.conf.ext p,',
            'deny topic /etc/foo/dovecot-deny.conf r,',
            'topic /usr/lib/dovecot/config s,',
        ]

        ruleset = TopicRuleset()
        for rule in rules:
            ruleset.add(TopicRule.parse(rule))

        perms = ruleset.get_perms_for_path(params[0], params[1], params[2])
        self. assertEqual(perms, expected)

# class TopicGetPermsForPath_2(CATest):  # testing bare rules
#     tests = [
#         #  path                                 audit   deny    expected
#         (('/etc/foo/dovecot.conf',              False,  False), {'allow': TopicRule.ALL,  'deny': TopicRule.ALL, 'paths': {'/etc/foo/*', '/etc/foo/dovecot.conf'                                     }    }),
#         (('/etc/foo/dovecot.conf',              True,   False), {'allow': {'r', 'p'}   ,  'deny': set()        , 'paths': {'/etc/foo/dovecot.conf'                                                   }    }),
#         (('/etc/foo/foo.conf',                  False,  False), {'allow': TopicRule.ALL,  'deny': TopicRule.ALL, 'paths': {'/etc/foo/*'                                                              }    }),
#         (('/etc/foo/dovecot-database.conf.ext', False,  False), {'allow': TopicRule.ALL,  'deny': TopicRule.ALL, 'paths': {'/etc/foo/*', '/etc/foo/dovecot-database.conf.ext'                        }    }),
#         (('/etc/foo/auth.d/authfoo.conf',       False,  False), {'allow': TopicRule.ALL,  'deny': TopicRule.ALL, 'paths': {'/etc/foo/{auth,conf}.d/*.conf', '/etc/foo/{auth,conf}.d/authfoo.conf'    }    }),
#         (('/etc/foo/auth.d/authfoo.conf',       True,   False), {'allow': {'p'     }   ,  'deny': set()        , 'paths': {'/etc/foo/{auth,conf}.d/authfoo.conf'                                     }    }),
#         (('/etc/foo/dovecot-deny.conf',         False,  False), {'allow': TopicRule.ALL,  'deny': TopicRule.ALL, 'paths': {'/etc/foo/*', '/etc/foo/dovecot-deny.conf'                                }    }),
#         (('/foo/bar',                           False,  True ), {'allow': set()        ,  'deny': TopicRule.ALL, 'paths': set()                                                                           }),
#         (('/etc/foo/dovecot-deny.conf',         False,  True ), {'allow': set()        ,  'deny': TopicRule.ALL, 'paths': {'/etc/foo/dovecot-deny.conf'                                              }    }),
#         (('/etc/foo/foo.conf',                  False,  True ), {'allow': set()        ,  'deny': TopicRule.ALL, 'paths': set()                                                                           }),
#     ]
#
#     def _run_test(self, params, expected):
#         rules = [
#             'topic /etc/foo/* r,',
#             'audit topic /etc/foo/dovecot.conf rps,',
#             'topic /etc/foo/{auth,conf}.d/*.conf r,',
#             'audit topic /etc/foo/{auth,conf}.d/authfoo.conf p,',
#             'topic /etc/foo/dovecot-database.conf.ext p,',
#             'deny topic /etc/foo/dovecot-deny.conf r,',
#             # 'topic,',
#             # 'deny topic,',
#         ]
#
#         ruleset = TopicRuleset()
#         for rule in rules:
#             ruleset.add(TopicRule.parse(rule))
#
#         perms = ruleset.get_perms_for_path(params[0], params[1], params[2])
#         self. assertEqual(perms, expected)


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=2)

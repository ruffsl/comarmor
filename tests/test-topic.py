#!/usr/bin/python3
# ----------------------------------------------------------------------
#    Copyright (C) 2015 Christian Boltz <apparmor@cboltz.de>
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

import unittest
from collections import namedtuple
from common_test import CATest, setup_all_loops

from comarmor.rule.topic import TopicRule, TopicRuleset
from comarmor.rule import BaseRule
import comarmor.severity as severity
from apparmor.common import AppArmorException, AppArmorBug
from comarmor.common import ComArmorException, ComArmorBug
# from apparmor.logparser import ReadLog
from apparmor.translations import init_translation
_ = init_translation()

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

# class FileTestParseFromLog(FileTest):
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
#         #FileRule#     path,                 perms,                         exec_perms, target,         owner,  file_keyword,   leading_perms
#         #obj = FileRule(parsed_event['name'], parsed_event['denied_mask'],   None,       FileRule.ALL,   False,  False,          False,         )
#         obj = FileRule(parsed_event['name'], 'r',                           None,       FileRule.ALL,   False,  False,          False,         )
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
        sev_db = severity.TopicSeverity('topic-severity.db', 'unknown')
        obj = TopicRule.parse(params)
        rank = obj.severity(sev_db)
        self.assertEqual(rank, expected)

class FileLogprofHeaderTest(AATest):
    tests = [
        # log event                        old perms ALL / owner
        (['file,',                              set(),      set()       ], [                               _('Path'), _('ALL'),                                         _('New Mode'), _('ALL')                 ]),
        (['/foo r,',                            set(),      set()       ], [                               _('Path'), '/foo',                                           _('New Mode'), 'r'                      ]),
        (['file /bar Px -> foo,',               set(),      set()       ], [                               _('Path'), '/bar',                                           _('New Mode'), 'Px -> foo'              ]),
        (['deny file,',                         set(),      set()       ], [_('Qualifier'), 'deny',        _('Path'), _('ALL'),                                         _('New Mode'), _('ALL')                 ]),
        (['allow file /baz rwk,',               set(),      set()       ], [_('Qualifier'), 'allow',       _('Path'), '/baz',                                           _('New Mode'), 'rwk'                    ]),
        (['audit file /foo mr,',                set(),      set()       ], [_('Qualifier'), 'audit',       _('Path'), '/foo',                                           _('New Mode'), 'mr'                     ]),
        (['audit deny /foo wk,',                set(),      set()       ], [_('Qualifier'), 'audit deny',  _('Path'), '/foo',                                           _('New Mode'), 'wk'                     ]),
        (['owner file /foo ix,',                set(),      set()       ], [                               _('Path'), '/foo',                                           _('New Mode'), 'owner ix'               ]),
        (['audit deny file /foo rlx -> /baz,',  set(),      set()       ], [_('Qualifier'), 'audit deny',  _('Path'), '/foo',                                           _('New Mode'), 'rlx -> /baz'            ]),
        (['/foo rw,',                           set('r'),   set()       ], [                               _('Path'), '/foo',         _('Old Mode'), _('r'),            _('New Mode'), _('rw')                  ]),
        (['/foo rw,',                           set(),      set('rw')   ], [                               _('Path'), '/foo',         _('Old Mode'), _('owner rw'),     _('New Mode'), _('rw')                  ]),
        (['/foo mrw,',                          set('r'),   set('k')    ], [                               _('Path'), '/foo',         _('Old Mode'), _('r + owner k'),  _('New Mode'), _('mrw')                 ]),
        (['/foo mrw,',                          set('r'),   set('rk')   ], [                               _('Path'), '/foo',         _('Old Mode'), _('r + owner k'),  _('New Mode'), _('mrw')                 ]),
   ]

    def _run_test(self, params, expected):
        obj = FileRule._parse(params[0])
        if params[1] or params[2]:
            obj.original_perms = {'allow': { 'all': params[1], 'owner': params[2]}}
        self.assertEqual(obj.logprof_header(), expected)

    def test_empty_original_perms(self):
        obj = FileRule._parse('/foo rw,')
        obj.original_perms = {'allow': { 'all': set(), 'owner': set()}}
        self.assertEqual(obj.logprof_header(), [_('Path'), '/foo', _('New Mode'), _('rw')])

class FileEditHeaderTest(AATest):
    def _run_test(self, params, expected):
        rule_obj = FileRule.parse(params)
        self.assertEqual(rule_obj.can_edit, True)
        prompt, path_to_edit = rule_obj.edit_header()
        self.assertEqual(path_to_edit, expected)

    tests = [
        ('/foo/bar/baz r,',         '/foo/bar/baz'),
        ('/foo/**/baz r,',          '/foo/**/baz'),
    ]

    def test_edit_header_bare_file(self):
        rule_obj = FileRule.parse('file,')
        self.assertEqual(rule_obj.can_edit, False)
        with self.assertRaises(AppArmorBug):
            rule_obj.edit_header()

class FileValidateAndStoreEditTest(AATest):
    def _run_test(self, params, expected):
        rule_obj = FileRule('/foo/bar/baz', 'r', None, FileRule.ALL, False, False, False, log_event=True)

        self.assertEqual(rule_obj.validate_edit(params), expected)

        rule_obj.store_edit(params)
        self.assertEqual(rule_obj.get_raw(), '%s r,' % params)

    tests = [
        # edited path           match
        ('/foo/bar/baz',        True),
        ('/foo/bar/*',          True),
        ('/foo/bar/???',        True),
        ('/foo/xy**',           False),
        ('/foo/bar/baz/',       False),
    ]

    def test_validate_not_a_path(self):
        rule_obj = FileRule.parse('/foo/bar/baz r,')

        with self.assertRaises(AppArmorException):
            rule_obj.validate_edit('foo/bar/baz')

        with self.assertRaises(AppArmorException):
            rule_obj.store_edit('foo/bar/baz')

    def test_validate_edit_bare_file(self):
        rule_obj = FileRule.parse('file,')
        self.assertEqual(rule_obj.can_edit, False)

        with self.assertRaises(AppArmorBug):
            rule_obj.validate_edit('/foo/bar')

        with self.assertRaises(AppArmorBug):
            rule_obj.store_edit('/foo/bar')



## --- tests for FileRuleset --- #

class FileRulesTest(AATest):
    def test_empty_ruleset(self):
        ruleset = FileRuleset()
        ruleset_2 = FileRuleset()
        self.assertEqual([], ruleset.get_raw(2))
        self.assertEqual([], ruleset.get_clean(2))
        self.assertEqual([], ruleset_2.get_raw(2))
        self.assertEqual([], ruleset_2.get_clean(2))

    def test_ruleset_1(self):
        ruleset = FileRuleset()
        rules = [
            '         file             ,        ',
            '   file /foo rw,',
            '  file /bar r,',
        ]

        expected_raw = [
            'file             ,',
            'file /foo rw,',
            'file /bar r,',
            '',
        ]

        expected_clean = [
            'file /bar r,',
            'file /foo rw,',
            'file,',
            '',
        ]

        deleted = 0
        for rule in rules:
            deleted += ruleset.add(FileRule.parse(rule))

        self.assertEqual(deleted, 0)
        self.assertEqual(expected_raw, ruleset.get_raw())
        self.assertEqual(expected_clean, ruleset.get_clean())

    def test_ruleset_2(self):
        ruleset = FileRuleset()
        rules = [
            '/foo Px,',
            '/bar    Cx    ->     bar_child ,',
            'deny /asdf w,',
        ]

        expected_raw = [
            '  /foo Px,',
            '  /bar    Cx    ->     bar_child ,',
            '  deny /asdf w,',
             '',
        ]

        expected_clean = [
            '  deny /asdf w,',
            '',
            '  /bar Cx -> bar_child,',
            '  /foo Px,',
             '',
        ]

        deleted = 0
        for rule in rules:
            deleted += ruleset.add(FileRule.parse(rule))

        self.assertEqual(deleted, 0)
        self.assertEqual(expected_raw, ruleset.get_raw(1))
        self.assertEqual(expected_clean, ruleset.get_clean(1))

    def test_ruleset_cleanup_add_1(self):
        ruleset = FileRuleset()
        rules = [
            '/foo/bar r,',
            '/foo/baz rw,',
            '/foo/baz rwk,',
        ]

        rules_with_cleanup = [
            '/foo/* r,',
        ]

        expected_raw = [
            '  /foo/baz rw,',
            '  /foo/baz rwk,',
            '  /foo/* r,',
             '',
        ]

        expected_clean = [
            '  /foo/* r,',
            '  /foo/baz rw,',
            '  /foo/baz rwk,',
             '',
        ]

        deleted = 0
        for rule in rules:
            deleted += ruleset.add(FileRule.parse(rule))

        self.assertEqual(deleted, 0)  # rules[] are added without cleanup mode, so the superfluous '/foo/baz rw,' should be kept

        for rule in rules_with_cleanup:
            deleted += ruleset.add(FileRule.parse(rule), cleanup=True)

        self.assertEqual(deleted, 1)  # rules_with_cleanup made '/foo/bar r,' superfluous
        self.assertEqual(expected_raw, ruleset.get_raw(1))
        self.assertEqual(expected_clean, ruleset.get_clean(1))


#class FileDeleteTest(AATest):
#    pass

class FileGetRulesForPath(AATest):
    tests = [
        #  path                                 audit   deny    expected
        (('/etc/foo/dovecot.conf',              False,  False), ['/etc/foo/* r,', '/etc/foo/dovecot.conf rw,',                                  '']),
        (('/etc/foo/foo.conf',                  False,  False), ['/etc/foo/* r,',                                                               '']),
        (('/etc/foo/dovecot-database.conf.ext', False,  False), ['/etc/foo/* r,', '/etc/foo/dovecot-database.conf.ext w,',                      '']),
        (('/etc/foo/auth.d/authfoo.conf',       False,  False), ['/etc/foo/{auth,conf}.d/*.conf r,','/etc/foo/{auth,conf}.d/authfoo.conf w,',   '']),
        (('/etc/foo/dovecot-deny.conf',         False,  False), ['deny /etc/foo/dovecot-deny.conf r,', '', '/etc/foo/* r,',                     '']),
        (('/foo/bar',                           False,  True ), [                                                                                 ]),
        (('/etc/foo/dovecot-deny.conf',         False,  True ), ['deny /etc/foo/dovecot-deny.conf r,',                                          '']),
        (('/etc/foo/foo.conf',                  False,  True ), [                                                                                 ]),
        (('/etc/foo/owner.conf',                False,  False), ['/etc/foo/* r,', 'owner /etc/foo/owner.conf w,',                               '']),
    ]

    def _run_test(self, params, expected):
        rules = [
            '/etc/foo/* r,',
            '/etc/foo/dovecot.conf rw,',
            '/etc/foo/{auth,conf}.d/*.conf r,',
            '/etc/foo/{auth,conf}.d/authfoo.conf w,',
            '/etc/foo/dovecot-database.conf.ext w,',
            'owner /etc/foo/owner.conf w,',
            'deny /etc/foo/dovecot-deny.conf r,',
        ]

        ruleset = FileRuleset()
        for rule in rules:
            ruleset.add(FileRule.parse(rule))

        matching = ruleset.get_rules_for_path(params[0], params[1], params[2])
        self. assertEqual(matching.get_clean(), expected)


class FileGetPermsForPath_1(AATest):
    tests = [
        #  path                                 audit   deny    expected
        (('/etc/foo/dovecot.conf',              False,  False), {'allow': {'all': {'r', 'w'},    'owner': set()  },  'deny': {'all': set(),          'owner': set()   }, 'paths': {'/etc/foo/*', '/etc/foo/dovecot.conf'                                    }   }),
        (('/etc/foo/foo.conf',                  False,  False), {'allow': {'all': {'r'     },    'owner': set()  },  'deny': {'all': set(),          'owner': set()   }, 'paths': {'/etc/foo/*'                                                             }   }),
        (('/etc/foo/dovecot-database.conf.ext', False,  False), {'allow': {'all': {'r', 'w'},    'owner': set()  },  'deny': {'all': set(),          'owner': set()   }, 'paths': {'/etc/foo/*', '/etc/foo/dovecot-database.conf.ext'                       }   }),
        (('/etc/foo/auth.d/authfoo.conf',       False,  False), {'allow': {'all': {'r', 'w'},    'owner': set()  },  'deny': {'all': set(),          'owner': set()   }, 'paths': {'/etc/foo/{auth,conf}.d/*.conf', '/etc/foo/{auth,conf}.d/authfoo.conf'   }   }),
        (('/etc/foo/dovecot-deny.conf',         False,  False), {'allow': {'all': {'r'     },    'owner': set()  },  'deny': {'all': {'r'     },     'owner': set()   }, 'paths': {'/etc/foo/*', '/etc/foo/dovecot-deny.conf'                               }   }),
        (('/foo/bar',                           False,  True ), {'allow': {'all': set(),         'owner': set()  },  'deny': {'all': set(),          'owner': set()   }, 'paths': set()                                                                         }),
        (('/etc/foo/dovecot-deny.conf',         False,  True ), {'allow': {'all': set(),         'owner': set()  },  'deny': {'all': {'r'     },     'owner': set()   }, 'paths': {'/etc/foo/dovecot-deny.conf'                                             }   }),
        (('/etc/foo/foo.conf',                  False,  True ), {'allow': {'all': set(),         'owner': set()  },  'deny': {'all': set(),          'owner': set()   }, 'paths': set()                                                                         }),
        (('/usr/lib/dovecot/config',            False,  False), {'allow': {'all': set(),         'owner': set()  },  'deny': {'all': set(),          'owner': set()   }, 'paths': set()                     }),  # exec perms are not honored by get_perms_for_path()
    ]

    def _run_test(self, params, expected):
        rules = [
            '/etc/foo/* r,',
            '/etc/foo/dovecot.conf rw,',
            '/etc/foo/{auth,conf}.d/*.conf r,',
            '/etc/foo/{auth,conf}.d/authfoo.conf w,',
            '/etc/foo/dovecot-database.conf.ext w,',
            'deny /etc/foo/dovecot-deny.conf r,',
            '/usr/lib/dovecot/config ix,',
        ]

        ruleset = FileRuleset()
        for rule in rules:
            ruleset.add(FileRule.parse(rule))

        perms = ruleset.get_perms_for_path(params[0], params[1], params[2])
        self. assertEqual(perms, expected)

class FileGetPermsForPath_2(AATest):
    tests = [
        #  path                                 audit   deny    expected
        (('/etc/foo/dovecot.conf',              False,  False), {'allow': {'all': FileRule.ALL, 'owner': set()  },  'deny': {'all': FileRule.ALL,   'owner': set()  }, 'paths': {'/etc/foo/*', '/etc/foo/dovecot.conf'                                     }    }),
        (('/etc/foo/dovecot.conf',              True,   False), {'allow': {'all': {'r', 'w'},   'owner': set()  },  'deny': {'all': set(),          'owner': set()  }, 'paths': {'/etc/foo/dovecot.conf'                                                   }    }),
        (('/etc/foo/foo.conf',                  False,  False), {'allow': {'all': FileRule.ALL, 'owner': set()  },  'deny': {'all': FileRule.ALL,   'owner': set()  }, 'paths': {'/etc/foo/*'                                                              }    }),
        (('/etc/foo/dovecot-database.conf.ext', False,  False), {'allow': {'all': FileRule.ALL, 'owner': set()  },  'deny': {'all': FileRule.ALL,   'owner': set()  }, 'paths': {'/etc/foo/*', '/etc/foo/dovecot-database.conf.ext'                        }    }),
        (('/etc/foo/auth.d/authfoo.conf',       False,  False), {'allow': {'all': FileRule.ALL, 'owner': set()  },  'deny': {'all': FileRule.ALL,   'owner': set()  }, 'paths': {'/etc/foo/{auth,conf}.d/*.conf', '/etc/foo/{auth,conf}.d/authfoo.conf'    }    }),
        (('/etc/foo/auth.d/authfoo.conf',       True,   False), {'allow': {'all': {'w'     },   'owner': set()  },  'deny': {'all': set(),          'owner': set()  }, 'paths': {'/etc/foo/{auth,conf}.d/authfoo.conf'                                     }    }),
        (('/etc/foo/dovecot-deny.conf',         False,  False), {'allow': {'all': FileRule.ALL, 'owner': set()  },  'deny': {'all': FileRule.ALL,   'owner': set()  }, 'paths': {'/etc/foo/*', '/etc/foo/dovecot-deny.conf'                                }    }),
        (('/foo/bar',                           False,  True ), {'allow': {'all': set(),        'owner': set()  },  'deny': {'all': FileRule.ALL,   'owner': set()  }, 'paths': set()                                                                           }),
        (('/etc/foo/dovecot-deny.conf',         False,  True ), {'allow': {'all': set(),        'owner': set()  },  'deny': {'all': FileRule.ALL,   'owner': set()  }, 'paths': {'/etc/foo/dovecot-deny.conf'                                              }    }),
        (('/etc/foo/foo.conf',                  False,  True ), {'allow': {'all': set(),        'owner': set()  },  'deny': {'all': FileRule.ALL,   'owner': set()  }, 'paths': set()                                                                           }),
    #   (('/etc/foo/owner.conf',                False,  True ), {'allow': {'all': set(),        'owner': {'w'}  },  'deny': {'all': FileRule.ALL,   'owner': set()  }, 'paths': {'/etc/foo/owner.conf'                                                     }    }), # XXX doen't work yet
    ]

    def _run_test(self, params, expected):
        rules = [
            '/etc/foo/* r,',
            'audit /etc/foo/dovecot.conf rw,',
            '/etc/foo/{auth,conf}.d/*.conf r,',
            'audit /etc/foo/{auth,conf}.d/authfoo.conf w,',
            '/etc/foo/dovecot-database.conf.ext w,',
            'deny /etc/foo/dovecot-deny.conf r,',
            'file,',
            'owner /etc/foo/owner.conf w,',
            'deny file,',
        ]

        ruleset = FileRuleset()
        for rule in rules:
            ruleset.add(FileRule.parse(rule))

        perms = ruleset.get_perms_for_path(params[0], params[1], params[2])
        self. assertEqual(perms, expected)

class FileGetExecRulesForPath_1(AATest):
    tests = [
        ('/bin/foo',    ['audit /bin/foo ix,', '']                      ),
        ('/bin/bar',    ['deny /bin/bar x,', '']                        ),
        ('/foo',        []                                              ),
    ]

    def _run_test(self, params, expected):
        rules = [
            '/foo r,',
            'audit /bin/foo ix,',
            '/bin/b* Px,',
            'deny /bin/bar x,',
        ]

        ruleset = FileRuleset()
        for rule in rules:
            ruleset.add(FileRule.parse(rule))

        perms = ruleset.get_exec_rules_for_path(params)
        matches = perms.get_clean()
        self. assertEqual(matches, expected)

class FileGetExecRulesForPath_2(AATest):
    tests = [
        ('/bin/foo',    ['audit /bin/foo ix,', '']                      ),
        ('/bin/bar',    ['deny /bin/bar x,', '', '/bin/b* Px,', '']     ),
        ('/foo',        []                                              ),
    ]

    def _run_test(self, params, expected):
        rules = [
            '/foo r,',
            'audit /bin/foo ix,',
            '/bin/b* Px,',
            'deny /bin/bar x,',
        ]

        ruleset = FileRuleset()
        for rule in rules:
            ruleset.add(FileRule.parse(rule))

        perms = ruleset.get_exec_rules_for_path(params, only_exact_matches=False)
        matches = perms.get_clean()
        self. assertEqual(matches, expected)

class FileGetExecConflictRules_1(AATest):
    tests = [
        ('/bin/foo ix,',    ['/bin/foo Px,', '']                            ),
        ('/bin/bar Px,',    ['deny /bin/bar x,', '', '/bin/bar cx,', '']    ),
        ('/bin/bar cx,',    ['deny /bin/bar x,','',]                        ),
        ('/bin/foo r,',     []                                              ),
    ]

    def _run_test(self, params, expected):
        rules = [
            '/foo r,',
            'audit /bin/foo ix,',
            '/bin/foo Px,',
            '/bin/b* Px,',
            '/bin/bar cx,',
            'deny /bin/bar x,',
        ]

        ruleset = FileRuleset()
        for rule in rules:
            ruleset.add(FileRule.parse(rule))

        rule_obj = FileRule.parse(params)
        conflicts = ruleset.get_exec_conflict_rules(rule_obj)
        self. assertEqual(conflicts.get_clean(), expected)



setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=2)

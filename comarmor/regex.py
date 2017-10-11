import re
from apparmor.regex import RE_AUDIT_DENY, RE_COMMA_EOL, strip_quotes


RE_PATH                 = '/\S*|"/[^"]*"'  # filename (starting with '/') without spaces, or quoted filename.
RE_PROFILE_PATH         = '(?P<%s>(' + RE_PATH + '))'  # quoted or unquoted filename. %s is the match group name
RE_PROFILE_PATH_OR_VAR  = '(?P<%s>(' + RE_PATH + '|@{\S+}\S*|"@{\S+}[^"]*"))'  # quoted or unquoted filename or variable. %s is the match group name

# Profile parsing Regex

# RE_TOPIC_PERMS is as restrictive as possible, but might still cause mismatches when adding different rule types.
# Therefore parsing code should match against file rules only after trying to match all other rule types.
RE_TOPIC_PERMS = '(?P<%s>[spr]+)'

RE_PROFILE_TOPIC = re.compile(
    RE_AUDIT_DENY +
    '(' +
        '(?P<bare_topic>topic)' +  # bare 'file,'
    '|' + # or
        '(' +
            'topic\s+' +
            RE_PROFILE_PATH_OR_VAR % 'path' + '\s+' + RE_TOPIC_PERMS % 'perms' +  # path and perms
        ')' +
    ')' +
    RE_COMMA_EOL)

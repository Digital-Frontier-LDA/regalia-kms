import unittest

from tests.source_lexing import go_code


class GoSourceLexingTests(unittest.TestCase):
    def test_comments_are_removed_without_removing_literals(self):
        source = '''
// json:"comment_line"
type Settings struct {
    Live string `json:"live_path"` // json:"comment_tail"
    Text string `json:"literal_with_//_slashes"`
    Rune rune // '/'
}
/*
json:"comment_block"
flag.String("retired", "", "")
*/
'''
        code = go_code(source)
        self.assertIn('json:"live_path"', code)
        self.assertIn('json:"literal_with_//_slashes"', code)
        for comment_only in ('json:"comment_line"', 'json:"comment_tail"',
                             'json:"comment_block"', 'flag.String("retired"'):
            self.assertNotIn(comment_only, code)

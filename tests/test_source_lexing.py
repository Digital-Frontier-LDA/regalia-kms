import unittest

from tests.source_lexing import go_code, shell_code


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


class ShellHeredocLexingTests(unittest.TestCase):
    """Heredoc bodies are DATA and must never be lexed as code.

    The source checks that build on this module ask questions like "does this script call sudo" or
    "does it name a path that does not exist". A heredoc that stops being masked early feeds its
    own contents to those checks, which then report findings about text the shell never executes —
    or, worse, miss the real line because the masking swallowed it.
    """

    def test_an_indented_terminator_does_not_close_a_plain_heredoc(self):
        # POSIX: for `<<EOF` the terminator is the line "EOF" exactly. An indented EOF inside the
        # body is DATA. `line.strip()` accepted it, so everything after it was lexed as shell.
        source = ("cat <<EOF\n"
                  "    EOF\n"
                  "rm -rf /DISTINCTIVE\n"
                  "EOF\n"
                  "echo done\n")
        code = shell_code(source)
        self.assertNotIn("DISTINCTIVE", code,
                         "an indented terminator closed a plain heredoc, so its body was lexed "
                         f"as code:\n{code}")
        self.assertIn("echo done", code, "masking never ended; the rest of the file was lost")

    def test_a_tab_indented_terminator_closes_a_dash_heredoc(self):
        # `<<-` strips leading TABS from the terminator, so this one really does close it.
        source = ("cat <<-EOF\n"
                  "\tbody\n"
                  "\tEOF\n"
                  "echo after\n")
        code = shell_code(source)
        self.assertIn("echo after", code, f"a tab-indented terminator did not close <<-EOF:\n{code}")
        self.assertNotIn("body", code)

    def test_a_space_indented_terminator_does_not_close_a_dash_heredoc(self):
        # <<- strips tabs, not spaces. Accepting spaces ends the body early on a heredoc whose
        # data is deliberately space-aligned, which is most of them.
        source = ("cat <<-EOF\n"
                  "    EOF\n"
                  "rm -rf /DISTINCTIVE\n"
                  "\tEOF\n"
                  "echo after\n")
        code = shell_code(source)
        self.assertNotIn("DISTINCTIVE", code, f"spaces closed a <<- heredoc:\n{code}")
        self.assertIn("echo after", code)

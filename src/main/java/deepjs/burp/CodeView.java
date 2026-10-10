package deepjs.burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.util.Collection;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;

/**
 * A finding in the code it was read from: the source around it, with the
 * finding itself highlighted. A finding is a claim about some code, and this
 * is where the claim can be checked without opening the file and searching it.
 */
final class CodeView extends JPanel {

    private static final long serialVersionUID = 1L;
    private static final Color MARK = new Color(255, 170, 0, 110);         // legible on a light theme and a dark one

    private final JLabel where = new JLabel(" ");
    private final JTextArea code = new JTextArea(7, 80);
    private int from, to;

    CodeView() {
        super(new BorderLayout(0, 2));
        code.setEditable(false);
        code.setLineWrap(true);                             // a minified bundle is one line
        code.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        where.setBorder(BorderFactory.createEmptyBorder(2, 4, 0, 4));
        add(where, BorderLayout.NORTH);
        add(new JScrollPane(code), BorderLayout.CENTER);
    }

    /**
     * Show `span` between what stands before and after it in the source.
     * `concealed`: values that must not be readable (the "Mask values" option) — each is
     * replaced by its masked form wherever it appears, whole or cut by the edge of the excerpt.
     */
    void show(String location, String before, String span, String after, Collection<String> concealed) {
        before = printable(before);
        span = printable(span);
        StringBuilder text = new StringBuilder(before).append(span).append(printable(after));
        int[] mark = conceal(text, before.length(), before.length() + span.length(), concealed);
        from = mark[0];
        to = mark[1];
        where.setText(location);
        code.setText(text.toString());
        code.getHighlighter().removeAllHighlights();
        try {
            code.getHighlighter().addHighlight(from, to, new DefaultHighlighter.DefaultHighlightPainter(MARK));
        } catch (BadLocationException impossible) {
            // from and to lie inside the text just set
        }
        code.setCaretPosition(from);                        // scrolls the finding into view
    }

    /** Nothing to show, and why. */
    void clear(String message) {
        from = to = 0;
        where.setText(message);
        code.getHighlighter().removeAllHighlights();
        code.setText("");
    }

    String text() {
        return code.getText();
    }

    String highlighted() {
        return code.getText().substring(from, to);
    }

    /** Source as a text component can show it: no carriage returns, a dot for every other control character. */
    static String printable(String source) {
        StringBuilder out = new StringBuilder(source.length());
        for (int i = 0; i < source.length(); i++) {
            char c = source.charAt(i);
            if (c == '\n' || c == '\t' || !Character.isISOControl(c)) {
                out.append(c);
            } else if (c != '\r') {
                out.append('·');
            }
        }
        return out.toString();
    }

    /** Replace each of `values` in `text` by its masked form; returns where the span [from, to) is afterwards. */
    static int[] conceal(StringBuilder text, int from, int to, Collection<String> values) {
        for (String value : values) {
            if (value.length() < 6) {
                continue;
            }
            String masked = DeepJsTab.mask(value);
            for (int at = text.lastIndexOf(value); at >= 0; at = at == 0 ? -1 : text.lastIndexOf(value, at - 1)) {
                int end = at + value.length(), grown = masked.length() - value.length();
                text.replace(at, end, masked);
                if (end <= from) {
                    from += grown;
                    to += grown;
                } else if (at < to) {
                    from = Math.min(from, at);
                    to = Math.max(to, end) + grown;
                }
            }
            // the excerpt may begin or end inside the value: half a secret is not to be shown either
            for (int k = Math.min(value.length() - 1, text.length()); k >= 6; k--) {
                int tail = text.length() - k;
                if (text.substring(tail).equals(value.substring(0, k))) {
                    text.replace(tail, text.length(), value.substring(0, 2) + "…");
                    from = Math.min(from, text.length());
                    to = to > tail ? text.length() : to;
                    break;
                }
            }
            for (int k = Math.min(value.length() - 1, text.length()); k >= 6; k--) {
                if (text.substring(0, k).equals(value.substring(value.length() - k))) {
                    text.replace(0, k, "…");
                    from = from >= k ? from - k + 1 : 0;
                    to = to >= k ? to - k + 1 : Math.min(to, 1);
                    break;
                }
            }
        }
        return new int[]{from, Math.max(from, to)};
    }
}

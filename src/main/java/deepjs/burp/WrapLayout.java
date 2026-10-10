package deepjs.burp;

import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Insets;

/**
 * A row of controls that continues on the next line when the window is too
 * narrow for it. A plain FlowLayout at the top of a panel keeps the height of
 * one row, and what does not fit in that row is simply not there.
 */
final class WrapLayout extends FlowLayout {

    private static final long serialVersionUID = 1L;

    WrapLayout() {
        super(FlowLayout.LEFT, 8, 2);
    }

    @Override
    public Dimension preferredLayoutSize(Container target) {
        return size(target, true);
    }

    @Override
    public Dimension minimumLayoutSize(Container target) {
        return size(target, false);
    }

    private Dimension size(Container target, boolean preferred) {
        synchronized (target.getTreeLock()) {
            // the parent has its size before it asks this row how tall it wants to be
            Container parent = target.getParent();
            int width = parent == null || parent.getWidth() == 0 ? target.getWidth()
                    : parent.getWidth() - parent.getInsets().left - parent.getInsets().right;
            Insets insets = target.getInsets();
            int available = width <= 0 ? Integer.MAX_VALUE : width - insets.left - insets.right - 2 * getHgap();
            int row = 0, rowHeight = 0, widest = 0, height = 0;
            for (Component c : target.getComponents()) {
                if (!c.isVisible()) {
                    continue;
                }
                Dimension d = preferred ? c.getPreferredSize() : c.getMinimumSize();
                if (row > 0 && row + getHgap() + d.width > available) {
                    widest = Math.max(widest, row);
                    height += rowHeight + getVgap();
                    row = 0;
                    rowHeight = 0;
                }
                row += (row > 0 ? getHgap() : 0) + d.width;
                rowHeight = Math.max(rowHeight, d.height);
            }
            return new Dimension(Math.max(widest, row) + insets.left + insets.right + 2 * getHgap(),
                    height + rowHeight + insets.top + insets.bottom + 2 * getVgap());
        }
    }
}

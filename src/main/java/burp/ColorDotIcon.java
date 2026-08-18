package burp;

import burp.api.montoya.core.HighlightColor;
import java.awt.Color;
import java.awt.Component;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import javax.swing.Icon;

public class ColorDotIcon implements Icon {

    private final Color color;
    private final int size = 12;

    public ColorDotIcon(HighlightColor highlightColor) {
        this.color = getAwtColor(highlightColor);
    }

    private Color getAwtColor(HighlightColor highlightColor) {
        if (highlightColor == null) {
            return Color.GRAY;
        }
        switch (highlightColor) {
            case RED: return new Color(239, 68, 68);
            case ORANGE: return new Color(249, 115, 22);
            case YELLOW: return new Color(234, 179, 8);
            case GREEN: return new Color(34, 197, 94);
            case CYAN: return new Color(20, 184, 166);
            case BLUE: return new Color(59, 130, 246);
            case MAGENTA: return new Color(168, 85, 247);
            case PINK: return new Color(236, 72, 153);
            default: return new Color(156, 163, 175); // gray
        }
    }

    @Override
    public void paintIcon(Component c, Graphics g, int x, int y) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setColor(color);
        // Draw filled circle
        g2.fillOval(x, y + 1, size, size);
        // Draw thin border
        g2.setColor(color.darker());
        g2.drawOval(x, y + 1, size, size);
        g2.dispose();
    }

    @Override
    public int getIconWidth() {
        return size + 4;
    }

    @Override
    public int getIconHeight() {
        return size;
    }
}

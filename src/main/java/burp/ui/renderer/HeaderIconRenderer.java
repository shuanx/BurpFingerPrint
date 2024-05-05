package burp.ui.renderer;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import burp.util.UiUtils;

/**
 * @author： shaun
 * @create： 2024/3/27 21:20
 * @description：TODO
 */
public class HeaderIconRenderer extends DefaultTableCellRenderer {
    private static final Icon FILTER_ICON = UiUtils.getImageIcon("/icon/filterIcon.png", 17, 17);
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        // 保留原始行为
        Component comp = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        // 如果是类型列
        if (column == 6 || column == 7) {
            setIcon(FILTER_ICON);
            setHorizontalAlignment(JLabel.CENTER);
            setHorizontalTextPosition(JLabel.LEFT);
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        } else {
            setIcon(null);
        }
        return comp;
    }
}
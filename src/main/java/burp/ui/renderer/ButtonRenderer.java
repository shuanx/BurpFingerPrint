package burp.ui.renderer;

import javax.swing.*;
import javax.swing.table.TableCellRenderer;
import java.awt.*;

import burp.util.UiUtils;

/**
 * @author： shaun
 * @create： 2024/3/28 00:19
 * @description：TODO
 */
public class ButtonRenderer extends JPanel implements TableCellRenderer {
    private final JButton editButton;
    private final JButton deleteButton;
    private static final Icon EDIT_ICON = UiUtils.getImageIcon("/icon/editButton.png");
    private static final Icon DELETE_ICON = UiUtils.getImageIcon("/icon/deleteButton.png");


    public ButtonRenderer() {
        setBorder(BorderFactory.createLineBorder(Color.BLACK));
        setLayout(new FlowLayout(FlowLayout.CENTER, 5, 0));
        editButton = new JButton();
        editButton.setIcon(EDIT_ICON);
        deleteButton = new JButton();
        deleteButton.setIcon(DELETE_ICON);

        editButton.setPreferredSize(new Dimension(40, 20));
        deleteButton.setPreferredSize(new Dimension(40, 20));

        add(editButton);
        add(deleteButton);
        setBorder(BorderFactory.createEmptyBorder());
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        if (isSelected) {
            setBackground(table.getSelectionBackground());
        } else {
            setBackground(table.getBackground());
        }
        return this;
    }
}
package burp.ui.renderer;

import burp.util.UiUtils;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

public class IconTableCellRenderer extends DefaultTableCellRenderer {

    // 预加载并缓存图标
    private final Icon importantIcon = UiUtils.getImageIcon("/icon/weakPasswordSuccess.png", 15, 15);

    public IconTableCellRenderer() {
        setHorizontalAlignment(CENTER); // 设置居中
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        // 调用父类以保留默认行为
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        // 检查单元格值是否为“爆破成功”
        if ("爆破成功".equals(value)) {
            setIcon(importantIcon);
            setText(""); // 设置文本为空，因为我们只显示图标
        } else {
            setIcon(null); // 不显示图标
            setText(value != null ? value.toString() : ""); // 显示文本，如果值为null则为空字符串
        }

        return this;
    }
}

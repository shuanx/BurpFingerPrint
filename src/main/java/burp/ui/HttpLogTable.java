package burp.ui;

import burp.BurpExtender;
import burp.model.TableLogEntry;

import javax.swing.*;
import javax.swing.table.TableModel;
import javax.swing.table.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.Toolkit;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.JTable;

public class HttpLogTable extends JTable {
    private HttpLogTableModel httpLogTableModel;

    public HttpLogTableModel getHttpLogTableModel() {
        return httpLogTableModel;
    }


    public HttpLogTable(TableModel tableModel) {
        super(tableModel);
        this.httpLogTableModel = (HttpLogTableModel) tableModel;
        // 对于每个列，设置一个自定义的 TableCellRenderer，实现鼠标移动个表格某个数据的时候，能完整展示出来
        for (int column = 0; column < getColumnModel().getColumnCount(); column++) {
            getColumnModel().getColumn(column).setCellRenderer(new ToolTipTableCellRenderer());
        }
        // 添加鼠标事件监听器，实现用户表格某个数据的时候，直接复制
        this.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                // 检查是否是双击事件
                if (e.getClickCount() == 2) {
                    // 获取当前选中的单元格
                    int row = getSelectedRow();
                    int col = getSelectedColumn();

                    // 获取单元格的值
                    Object value = getValueAt(row, col);

                    // 复制值到剪贴板
                    if (value != null) {
                        String text = value.toString();
                        StringSelection selection = new StringSelection(text);
                        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                        clipboard.setContents(selection, selection);
                    }
                }
            }
        });
    }

    // 自定义的 TableCellRenderer，实现鼠标移动个表格某个数据的时候，能完整展示出来
    public class ToolTipTableCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (value != null) {
                label.setToolTipText(value.toString());
            }
            return label;
        }
    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend) {
        super.changeSelection(row, col, toggle, extend);
        // show the log entry for the selected row
        TableLogEntry logEntry = BurpExtender.log.get(row);
        FingerTab.requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
        FingerTab.responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
        FingerTab.resultDeViewer.setText(logEntry.resultDetail.getBytes());
        FingerTab.resultDeViewer.setEditable(false);
        FingerTab.currentlyDisplayedItem = logEntry.requestResponse;

    }

    public void decrementResultCount(String result) {
        JLabel label = FingerTab.resultMap.get(result);
        if (label != null) {
            int count = Integer.parseInt(label.getText().split(": ")[1]);
            if (count > 1) {
                label.setText(result + ": " + (count - 1));
            } else {
                FingerTab.tagsPanel.remove(label);
                FingerTab.resultMap.remove(result);
                FingerTab.tagsPanel.revalidate();
                FingerTab.tagsPanel.repaint();
            }
        }
    }

}

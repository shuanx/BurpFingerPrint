package burp.ui;

import burp.BurpExtender;
import javax.swing.JTable;

import javax.swing.table.AbstractTableModel;

public class HttpLogTableModel extends AbstractTableModel {
    public int getRowCount() {
        return BurpExtender.log.size();
    }

    public int getColumnCount() {
        return 9;
    }

    @Override
    public String getColumnName(int columnIndex) {

        switch (columnIndex)
        {
            case 0:
                return "#";
            case 1:
                return "Method";
            case 2:
                return "URL";
            case 3:
                return "Title";
            case 4:
                return "Status";
            case 5:
                return "Result";
            case 6:
                return "type";
            case 7:
                return "IsImportant";
            case 8:
                return "Time";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }


    public Object getValueAt(int rowIndex, int columnIndex) {
        // 对接log数据，底层会遍历该接口，获取所有的log的数据展示在burp的表格上
        LogEntry logEntry = BurpExtender.log.get(rowIndex);

        switch (columnIndex) {
            case 0:
                return logEntry.id;
            case 1:
                return logEntry.method;
            case 2:
                return logEntry.url.toString();
            case 3:
                return logEntry.title;
            case 4:
                return logEntry.status;
            case 5:
                return logEntry.result;
            case 6:
                return logEntry.type;
            case 7:
                return logEntry.isImportant;
            case 8:
                return logEntry.requestTime;
            default:
                return "";
        }
    }

    public void setRowCount() {
        for (LogEntry logEntry : BurpExtender.log) {
            FingerTab.logTable.decrementResultCount(logEntry.result);
        }
        BurpExtender.log.clear();
        fireTableDataChanged();
    }

    public void removeSelectedRows(JTable table) {
        int[] selectedRows = table.getSelectedRows();
        for (int i = selectedRows.length - 1; i >= 0; i--) {
            String result = getResultAt(selectedRows[i]);
            FingerTab.logTable.decrementResultCount(result);
            BurpExtender.log.remove(selectedRows[i]);
        }
        fireTableDataChanged();
    }

    public String getResultAt(int rowIndex) {
        return BurpExtender.log.get(rowIndex).result;
    }


}

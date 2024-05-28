package burp.ui.event;

import burp.BurpExtender;
import burp.model.TableLogModel;
import burp.ui.FingerTab;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.*;
import java.util.List;
import java.io.FileWriter;
import java.io.IOException;

import static burp.util.Utils.escapeCsv;

/**
 * @author： shaun
 * @create： 2024/3/27 21:41
 * @description：TODO
 */
public class FingerTabEventHandlers {
    public static MouseAdapter headerAddMouseListener(JTable logTable) {
        return new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (logTable.getColumnModel().getColumnIndexAtX(e.getX()) == 6) { // 假设类型列的索引是1
                    JPopupMenu filterMenu = new JPopupMenu();

                    // “全部”选项用于移除过滤
                    JMenuItem allItem = new JMenuItem("全部");
                    allItem.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            FingerTab.historyChoiceType = "全部";
                            FingerTab.historyChoiceJMenuItem = "全部";
                            FingerTab.setFlashButtonTrue();
                            FingerTab.filterTable("全部", "全部", null);
                        }
                    });
                    filterMenu.add(allItem);

                    filterMenu.add(new JSeparator()); // 分隔线

                    // 为每个独特的类型创建菜单项
                    for (String type : BurpExtender.getTags().fingerConfigTab.uniqueTypes) {
                        JMenuItem menuItem = new JMenuItem(type);
                        menuItem.addActionListener(new ActionListener() {
                            @Override
                            public void actionPerformed(ActionEvent e) {
                                FingerTab.historyChoiceJMenuItem = "全部";
                                FingerTab.historyChoiceType = type;
                                FingerTab.setFlashButtonFalse();
                                FingerTab.filterTable(type, "全部", null); // 根据选中的类型过滤表格
                            }
                        });
                        filterMenu.add(menuItem);
                    }

                    filterMenu.show(e.getComponent(), e.getX(), e.getY()); // 显示菜单
                } else if (logTable.getColumnModel().getColumnIndexAtX(e.getX()) == 7) {
                    JPopupMenu filterMenu = new JPopupMenu();

                    List<String> isImportantItem = new ArrayList<>(Arrays.asList("全部", "重点", "普通"));


                    // 为每个独特的类型创建菜单项
                    for (String itemName : isImportantItem) {
                        JMenuItem menuItem = new JMenuItem(itemName);
                        menuItem.addActionListener(new ActionListener() {
                            @Override
                            public void actionPerformed(ActionEvent e) {
                                if (itemName.equals("全部")) {
                                    FingerTab.setFlashButtonTrue();
                                    FingerTab.filterTable(FingerTab.historyChoiceType, FingerTab.historyChoiceJMenuItem, null); // 根据选中的类型过滤表格
                                } else if (itemName.equals("重点")) {
                                    FingerTab.setFlashButtonFalse();
                                    FingerTab.filterTable(FingerTab.historyChoiceType, FingerTab.historyChoiceJMenuItem, true); // 根据选中的类型过滤表格
                                } else if (itemName.equals("普通")) {
                                    FingerTab.setFlashButtonFalse();
                                    FingerTab.filterTable(FingerTab.historyChoiceType, FingerTab.historyChoiceJMenuItem, false); // 根据选中的类型过滤表格
                                }

                            }
                        });
                        filterMenu.add(menuItem);
                    }

                    filterMenu.show(e.getComponent(), e.getX(), e.getY()); // 显示菜单
                }
                }


        };
    }


    public static TableModelListener modelAddTableModelListener(DefaultTableModel model, JPanel tagsPanel, HashMap<String, JLabel> resultMap, JTable logTable) {
        return new TableModelListener() {
            private static final int MAX_LABEL = 20;
            List<String> labelList = new ArrayList<>();
            int ADD_LABEL_NUMBER = 0;
            @Override
            public void tableChanged(TableModelEvent e) {
                HashMap<String, Integer> resultCounts = BurpExtender.getDataBaseService().getResultCountsFromDatabase();
                // 创建一个 TreeMap 并进行反向排序
                TreeMap<Integer, LinkedList<String>> sortedResults = new TreeMap<>(Collections.reverseOrder());
                for (Map.Entry<String, Integer> entry : resultCounts.entrySet()) {
                    sortedResults.computeIfAbsent(entry.getValue(), k -> new LinkedList<>()).add(entry.getKey());
                }
                List<String> tmpList = new ArrayList<>();
                // 添加新的结果标签
                for (Map.Entry<Integer, LinkedList<String>> entry : sortedResults.entrySet()) {
                    Integer count = entry.getKey();
                    for (String result : entry.getValue()) {
                        if(ADD_LABEL_NUMBER == MAX_LABEL){
                            tmpList.add("...(0)");
                            ADD_LABEL_NUMBER += 1;
                            continue;
                        }
                        if(ADD_LABEL_NUMBER > MAX_LABEL){
                            continue;
                        }
                        ADD_LABEL_NUMBER += 1;
                        tmpList.add(result + " (" + count + ")");

                    }
                }
                if(!labelList.equals(tmpList)){
                    labelList = tmpList;
                    clearAllResultLabels(tagsPanel);
                    for (String result : tmpList){
                        addNewResultLabel(result);
                    }
                }
                ADD_LABEL_NUMBER = 0;
            }

            public void addNewResultLabel(String result) {
                // 创建新的标签
                JLabel newLabel = new JLabel(result);
                newLabel.setOpaque(true);  // 设置为不透明
                newLabel.setBackground(new Color(200, 200, 200));  // 设置背景颜色为浅灰色
                newLabel.setForeground(Color.BLACK);  // 设置字体颜色为黑色

                // 为标签添加一个有颜色的边框，边框内有5像素的填充
                newLabel.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(new Color(100, 100, 100), 1),  // 外部边框，颜色为深灰色，宽度为2像素
                        BorderFactory.createEmptyBorder(5, 5, 5, 5)  // 内部填充，宽度为5像素
                ));


                if (!result.contains("...(")){

                    newLabel.addMouseListener(new MouseAdapter() {
                        @Override
                        public void mouseClicked(MouseEvent e) {
                            // 取消之前选中标签的颜色
                            if (FingerTab.currentSelectedLabel != null) {
                                FingerTab.currentSelectedLabel.setBackground(new Color(200, 200, 200)); // 还原默认背景色
                            }
                            FingerTab.setFlashButtonFalse();
                            // 设置当前点击的标签为选中状态
                            newLabel.setBackground(new Color(150, 150, 150)); // 选中状态的背景色
                            FingerTab.currentSelectedLabel = newLabel; //
                            // 当用户点击某个标签时，展示所有包含该标签文本的结果
                            String filterWithoutCount = result.replaceAll("\\(.*\\)", "").trim();
                            FingerTab.historyChoiceJMenuItem = filterWithoutCount;
                            FingerTab.historyChoiceType = "全部";
                            FingerTab.filterTable("全部", filterWithoutCount, null);
                        }
                    });
                }


                // 添加新的标签到面板和 resultMap
                tagsPanel.add(newLabel);
                resultMap.put(result, newLabel);
                // 重新验证和重绘面板
                tagsPanel.revalidate();
                tagsPanel.repaint();
            }



        };
    }


    public static ActionListener btnClearAddActionListener(DefaultTableModel model, JLabel lbRequestCount, JLabel lbSuccessCount){
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 清除表格数据
                lbRequestCount.setText("0");
                lbSuccessCount.setText("0");
                model.setRowCount(0);
                BurpExtender.getDataBaseService().clearTableDataTable();
                BurpExtender.getDataBaseService().clearRequestsResponseTable();
                model.fireTableDataChanged();
            }
        };
    }

    public static ActionListener exportItemAddActionListener() {
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 创建一个文件选择器实例
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Save As"); // 设置对话框标题
                fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                fileChooser.setAcceptAllFileFilterUsed(false); // 取消所有文件过滤
                fileChooser.addChoosableFileFilter(new FileNameExtensionFilter("CSV Files", "csv")); // 只允许CSV文件格式

                // 设置默认的文件名
                fileChooser.setSelectedFile(new File("BurpFingerPrint-TableData.csv"));

                // 弹出保存对话框
                int userSelection = fileChooser.showSaveDialog(null);

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    // 获取用户选择的文件
                    File fileToSave = fileChooser.getSelectedFile();
                    String filePath = fileToSave.getAbsolutePath();
                    // 确保文件有.csv扩展名
                    if (!filePath.endsWith(".csv")) {
                        filePath += ".csv";
                    }

                    // 获取所有数据模型
                    List<TableLogModel> allTableDataModels = BurpExtender.getDataBaseService().getAllTableDataModels();

                    // 创建CSV文件并写入数据
                    try (FileWriter csvWriter = new FileWriter(filePath)) {
                        // 写入标题行（根据TableLogModel的字段）
                        csvWriter.append("PID,URL,Method,Title,Status,Result,Type,IsImportant,ResultInfo,Host,Port,Protocol,RequestResponseIndex,Time\n");

                        // 遍历所有的数据模型并写入CSV
                        for (TableLogModel model : allTableDataModels) {
                            csvWriter.append(escapeCsv(String.valueOf(model.getPid())) + ",");
                            csvWriter.append(escapeCsv(model.getUrl()) + ",");
                            csvWriter.append(escapeCsv(model.getMethod()) + ",");
                            csvWriter.append(escapeCsv(model.getTitle()) + ",");
                            csvWriter.append(escapeCsv(model.getStatus()) + ",");
                            csvWriter.append(escapeCsv(model.getResult()) + ",");
                            csvWriter.append(escapeCsv(model.getType()) + ",");
                            csvWriter.append(escapeCsv(String.valueOf(model.getIsImportant())) + ",");
                            csvWriter.append(escapeCsv(model.getResultInfo()) + ",");
                            csvWriter.append(escapeCsv(model.getHost()) + ",");
                            csvWriter.append(escapeCsv(String.valueOf(model.getPort())) + ",");
                            csvWriter.append(escapeCsv(model.getProtocol()) + ",");
                            csvWriter.append(escapeCsv(String.valueOf(model.getRequestResponseIndex())) + ",");
                            csvWriter.append(escapeCsv(model.getTime()));
                            csvWriter.append("\n");
                        }
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                }
            }
        };
    }


    public static ActionListener clearItemAddActionListener(DefaultTableModel model, JTable logTable, JLabel lbSuccessCount){
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectRow = logTable.getSelectedRow();
                if (selectRow >= 0){
                    String url = model.getValueAt(selectRow, 2).toString();
                    BurpExtender.getDataBaseService().deleteDataByUrl(url);
                }
                FingerTab.filterTable(FingerTab.historyChoiceType, FingerTab.historyChoiceJMenuItem, null);
                lbSuccessCount.setText(Integer.toString(BurpExtender.getDataBaseService().getTableDataCount()));
            }
        };
    }
//
//
//    public static ActionListener allFingerprintsButtonAddActionListener(HttpLogTable logTable, JToggleButton allFingerprintsButton){
//        return new ActionListener() {
//            @Override
//            public void actionPerformed(ActionEvent e) {
//                // 检查按钮状态并切换
//                if (allFingerprintsButton.isSelected() && logTable != null) {
//                    // 按钮选中状态，应用过滤器以仅显示 isImportant 列为 true 的行
//                    RowFilter<TableModel, Integer> importanceFilter = new RowFilter<TableModel, Integer>() {
//                        @Override
//                        public boolean include(Entry<? extends TableModel, ? extends Integer> entry) {
//                            // 假设 isImportant 是第7列（注意列索引从0开始计数）
//                            Boolean isImportant = (Boolean) entry.getValue(7); // 根据您的表格实际的列索引来调整
//                            return isImportant != null && isImportant;
//                        }
//                    };
//                    ((TableRowSorter<TableModel>) logTable.getRowSorter()).setRowFilter(importanceFilter);
//                } else if (logTable != null) {
//                    // 按钮未选中状态，移除过滤器以显示所有行
//                    ((TableRowSorter<TableModel>) logTable.getRowSorter()).setRowFilter(null);
//                }
//                // 更新FingerConfigTab中的按钮状态
//                FingerConfigTab.allFingerprintsButton.setSelected(allFingerprintsButton.isSelected());
//                // 调用FingerConfigTab中的toggleFingerprintsDisplay方法
//                FingerConfigTab.toggleFingerprintsDisplay(false, allFingerprintsButton.isSelected());
//            }
//        };
//    }

    public static void clearAllResultLabels(JPanel tagsPanel) {
        for (Component component : tagsPanel.getComponents()) {
            if (component instanceof JLabel) {
                JLabel label = (JLabel) component;
                // 如果标签的文本不是"全部"，则移除
                if (!"全部".equals(label.getText())) {
                    tagsPanel.remove(component);
                }
            }
        }
        tagsPanel.revalidate();
        tagsPanel.repaint();
    }
}
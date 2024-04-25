package burp.model;

import burp.BurpExtender;
import burp.util.Utils;
import com.google.gson.Gson;

import java.nio.file.Paths;
import java.sql.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.time.Duration;
import java.time.LocalDateTime;

public class DatabaseService {

    private static final String CONNECTION_STRING = "jdbc:sqlite:" + Paths.get(Utils.getExtensionFilePath(BurpExtender.getCallbacks()), "BurpFinderPrint.db").toAbsolutePath().toString();;
    private Gson gson = new Gson();

    private static DatabaseService instance;
    private Connection connection;

    private DatabaseService() {
        initializeConnection();
        initializeDatabase();
    }

    public static synchronized DatabaseService getInstance() {
        if (instance == null) {
            instance = new DatabaseService();
        }
        return instance;
    }

    private Connection connect() throws SQLException {
        return DriverManager.getConnection(CONNECTION_STRING);
    }

    private void initializeConnection() {
        try {
            // 注册 SQLite 驱动程序
            Driver driver = new org.sqlite.JDBC();
            DriverManager.registerDriver(driver);
            connection = DriverManager.getConnection(CONNECTION_STRING);
            // Enable foreign key support
            connection.createStatement().execute("PRAGMA foreign_keys = ON");
            BurpExtender.getStdout().println("[+] load db connect success~ ");
        } catch (Exception e) {
            BurpExtender.getStderr().println("[!] load db connect Fail, befalse:");
            e.printStackTrace(BurpExtender.getStderr());
        }
    }

    private synchronized void initializeDatabase() {
        // 用于创建表的SQL语句
        String sql = "CREATE TABLE IF NOT EXISTS table_data (\n"
                + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
                + " pid INTEGER, \n"
                + " url TEXT NOT NULL,\n"
                + " method TEXT ,\n"
                + " title TEXT,\n"
                + " status TEXT,\n"
                + " result TEXT,\n"
                + " type TEXT,\n"
                + " is_important INTEGER,\n"
                + " time TEXT,\n"
                + " result_info TEXT,\n"
                + "request_response_index INTEGER, \n"
                + "host TEXT, \n"
                + "port INTEGER, \n"
                + "protocol TEXT\n"
                + ");";

        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
            BurpExtender.getStdout().println("[+] create table_data db success~");
        } catch (Exception e) {
            BurpExtender.getStderr().println("[!] create table_data db failed, because：");
            e.printStackTrace(BurpExtender.getStderr());
        }

        // 用来创建数据库requestResponse
        String requestsResponseSQL = "CREATE TABLE IF NOT EXISTS requests_response (\n"
                + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
                + " url TEXT NOT NULL,\n"
                + " request BLOB, \n"
                + " response BLOB\n"
                + ");";

        try (Statement stmt = connection.createStatement()) {
            stmt.execute(requestsResponseSQL);
            BurpExtender.getStdout().println("[+] create requests response db success~");
        } catch (Exception e) {
            BurpExtender.getStderr().println("[!] create requests response db failed, because：");
            e.printStackTrace(BurpExtender.getStderr());
        }
    }

    public Connection getConnection() {
        return connection;
    }

    public synchronized int insertOrUpdateLogEntry(TableLogModel logEntry) {
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String checkSql = "SELECT id, result, result_info, status, request_response_index FROM table_data WHERE url = ?";

        try (Connection conn = this.connect();
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            // 检查记录是否存在
            checkStmt.setString(1, Utils.getUriFromUrl(logEntry.getUrl()));
            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                // 记录存在，更新记录

                String updateSql = "UPDATE table_data SET method = ?, title = ?, status = ?, result = ?, type = ?, is_important = ?, result_info = ?, host = ?, port = ?, protocol = ?, time = ?, request_response_index = ? WHERE url = ?";
                generatedId = rs.getInt("id");
                String result = rs.getString("result");
                String status = rs.getString("status");
                int request_response_index = rs.getInt("request_response_index");

                for (String oneRs : logEntry.getResult().split(", ")){
                    if (!result.contains(oneRs)){
                        result = result + ", " + oneRs;
                    }
                }

                if (logEntry.getStatus().equals("200")){
                    request_response_index = logEntry.getRequestResponseIndex();
                    status = logEntry.getStatus();
                }

                try (PreparedStatement updateStmt = conn.prepareStatement(updateSql)) {
                    updateStmt.setString(1, logEntry.getMethod());
                    updateStmt.setString(2, logEntry.getTitle());
                    updateStmt.setString(3, status);
                    updateStmt.setString(4, result);
                    updateStmt.setString(5, logEntry.getType());
                    updateStmt.setBoolean(6, logEntry.getIsImportant());
                    updateStmt.setString(7, rs.getString("result_info") + "\r\n\r\n" + logEntry.getResultInfo());
                    updateStmt.setString(8, logEntry.getHost());
                    updateStmt.setInt(9, logEntry.getPort());
                    updateStmt.setString(10, logEntry.getProtocol());
                    updateStmt.setString(11, logEntry.getUrl());
                    updateStmt.setString(12, logEntry.getTime());
                    updateStmt.setInt(13, request_response_index);
                    updateStmt.executeUpdate();
                }
            } else {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO table_data (pid, url, method, title, status, result, type, is_important, result_info, request_response_index, host, port, protocol, time) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    insertStmt.setInt(1, logEntry.getPid());
                    insertStmt.setString(2, logEntry.getUrl());
                    insertStmt.setString(3, logEntry.getMethod());
                    insertStmt.setString(4, logEntry.getTitle());
                    insertStmt.setString(5, logEntry.getStatus());
                    insertStmt.setString(6, logEntry.getResult());
                    insertStmt.setString(7, logEntry.getType());
                    insertStmt.setBoolean(8, logEntry.getIsImportant());
                    insertStmt.setString(9, logEntry.getResultInfo());
                    insertStmt.setInt(10, logEntry.getRequestResponseIndex());
                    insertStmt.setString(11, logEntry.getHost());
                    insertStmt.setInt(12, logEntry.getPort());
                    insertStmt.setString(13, logEntry.getProtocol());
                    insertStmt.setString(14, logEntry.getTime());
                    insertStmt.executeUpdate();

                    // 获取生成的键值
                    try (ResultSet generatedKeys = insertStmt.getGeneratedKeys()) {
                        if (generatedKeys.next()) {
                            generatedId = generatedKeys.getInt(1); // 获取生成的ID
                        }
                    }
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error inserting or updating table_data: ");
            e.printStackTrace(BurpExtender.getStderr());
        }

        return generatedId; // 返回ID值，无论是更新还是插入
    }

    public synchronized List<TableLogModel> getAllTableDataModels() {
        List<TableLogModel> allTableDataModels = new ArrayList<>();
        String sql = "SELECT * FROM table_data";

        try (Connection conn = this.connect();
             Statement stmt  = conn.createStatement();
             ResultSet rs    = stmt.executeQuery(sql)) {

            // loop through the result set
            while (rs.next()) {
                TableLogModel model = new TableLogModel(
                        rs.getInt("pid"),
                        rs.getString("url"),
                        rs.getString("method"),
                        rs.getString("title"),
                        rs.getString("status"),
                        rs.getString("result"),
                        rs.getString("type"),
                        rs.getInt("is_important") != 0, // Convert to Boolean
                        rs.getString("result_info"),
                        Utils.iHttpService(rs.getString("host"), rs.getInt("port"), rs.getString("protocol")),
                        rs.getInt("request_response_index"),
                        rs.getString("time")
                );
                // Assuming you have a constructor that matches these parameters.
                allTableDataModels.add(model);
            }
        } catch (SQLException e) {
            BurpExtender.getStderr().println("[-] Error retrieving all records from table_data: ");
            e.printStackTrace(BurpExtender.getStderr());
        }
        return allTableDataModels;
    }

    public synchronized HashMap<String, Integer> getResultCountsFromDatabase() {
        HashMap<String, Integer> resultCounts = new HashMap<>();

        // 调用 getAllTableDataModels() 方法以从数据库获取所有记录
        List<TableLogModel> allTableDataModels = getAllTableDataModels();

        // 遍历所有记录
        for (TableLogModel model : allTableDataModels) {
            String result = model.getResult(); // 获取结果值
            if (result != null && !result.trim().isEmpty()) {
                String[] parts = result.split(", "); // 根据", "进行切分
                for (String part : parts) {
                    resultCounts.put(part, resultCounts.getOrDefault(part, 0) + 1); // 添加到映射中进行去重，并计数
                }
            }
        }

        return resultCounts; // 返回包含每个不同结果出现次数的 HashMap
    }
    public synchronized List<TableLogModel> getTableDataModelsByFilter(String typeFilter, String resultFilter, Boolean isImportantFilter) {
        List<TableLogModel> filteredTableDataModels = new ArrayList<>();
        // Start with a base SQL query
        StringBuilder sqlBuilder = new StringBuilder("SELECT * FROM table_data WHERE 1=1");

        // If typeFilter is not "全部", add it to the query
        if (!"全部".equals(typeFilter)) {
            sqlBuilder.append(" AND type LIKE ?");
        }
        // If resultFilter is not "全部", add it to the query
        if (!"全部".equals(resultFilter)) {
            sqlBuilder.append(" AND result LIKE ?");
        }
        // If isImportantFilter is not null, add it to the query
        if (isImportantFilter != null) {
            sqlBuilder.append(" AND is_important = ?");
        }

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sqlBuilder.toString())) {

            // Set the parameters to the prepared statement
            int paramIndex = 1;
            if (!"全部".equals(typeFilter)) {
                pstmt.setString(paramIndex++, "%" + typeFilter + "%");
            }
            if (!"全部".equals(resultFilter)) {
                pstmt.setString(paramIndex++, "%" + resultFilter + "%");
            }
            if (isImportantFilter != null) {
                pstmt.setInt(paramIndex, isImportantFilter ? 1 : 0);
            }

            ResultSet rs = pstmt.executeQuery();

            // Loop through the result set
            while (rs.next()) {
                TableLogModel model = new TableLogModel(
                        rs.getInt("pid"),
                        rs.getString("url"),
                        rs.getString("method"),
                        rs.getString("title"),
                        rs.getString("status"),
                        rs.getString("result"),
                        rs.getString("type"),
                        rs.getInt("is_important") != 0, // Convert to Boolean
                        rs.getString("result_info"),
                        Utils.iHttpService(rs.getString("host"), rs.getInt("port"), rs.getString("protocol")),
                        rs.getInt("request_response_index"),
                        rs.getString("time")
                );
                // Assuming you have a constructor that matches these parameters.
                filteredTableDataModels.add(model);
            }
        } catch (SQLException e) {
            BurpExtender.getStderr().println("[-] Error retrieving filtered records from table_data: ");
            e.printStackTrace(BurpExtender.getStderr());
        }
        return filteredTableDataModels;
    }


    public synchronized void deleteDataByUrl(String url) {
        // 删除SQL语句
        String sql = "DELETE FROM table_data WHERE url = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            // 设置参数
            pstmt.setString(1, url);
            // 执行删除操作
            pstmt.executeUpdate();

        } catch (SQLException e) {
            BurpExtender.getStderr().println("[!] Error deleting data from table_data with URL: " + url);
            e.printStackTrace(BurpExtender.getStderr());
        }
    }

    // 根据URL查询table_data表中的数据
    public synchronized TableLogModel getTableDataByUrl(String url) {
        String sql = "SELECT * FROM table_data WHERE url = ?";

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, url);
            ResultSet rs = pstmt.executeQuery();
                if (rs.next()) {
                    TableLogModel model = new TableLogModel(
                            rs.getInt("pid"),
                            rs.getString("url"),
                            rs.getString("method"),
                            rs.getString("title"),
                            rs.getString("status"),
                            rs.getString("result"),
                            rs.getString("type"),
                            rs.getInt("is_important") != 0, // Convert to Boolean
                            rs.getString("result_info"),
                            Utils.iHttpService(rs.getString("host"), rs.getInt("port"), rs.getString("protocol")),
                            rs.getInt("request_response_index"),
                            rs.getString("time")
                    );
                    return model;
            }
        } catch (SQLException e) {
            e.printStackTrace(); // 或更复杂的错误处理
        }
        return null;
    }

    public synchronized int getTableDataCount() {
        // 查询表格行数的SQL语句
        String sql = "SELECT COUNT(*) AS rowcount FROM table_data";

        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            // 如果查询结果存在，返回第一行的计数
            if (rs.next()) {
                int count = rs.getInt("rowcount");
                BurpExtender.getStdout().println("[+] Table table_data has " + count + " rows.");
                return count;
            }
        } catch (SQLException e) {
            BurpExtender.getStderr().println("[!] Error getting row count from table_data");
            e.printStackTrace(BurpExtender.getStderr());
        }
        // 如果查询失败，返回0或者适当的错误代码
        return 0;
    }

    public synchronized void clearRequestsResponseTable() {
        String sql = "DELETE FROM requests_response"; // 用 DELETE 语句来清空表

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.executeUpdate();
            BurpExtender.getStdout().println("[-] requests_response table has been cleared.");
        } catch (Exception e) {
            BurpExtender.getStderr().println("Error clearing requests_response table: ");
            e.printStackTrace(BurpExtender.getStderr());
        }
    }

    public synchronized void clearTableDataTable() {
        String sql = "DELETE FROM table_data"; // 用 DELETE 语句来清空表

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.executeUpdate();
            BurpExtender.getStdout().println("[-] table_data table has been cleared.");
        } catch (Exception e) {
            BurpExtender.getStderr().println("Error clearing table_data table: ");
            e.printStackTrace(BurpExtender.getStderr());
        }
    }


    // 关闭数据库连接的方法
    public void closeConnection() {
        try {
            if (this.connection != null && !this.connection.isClosed()) {
                this.connection.close();
            }
        } catch (SQLException ex) {
            BurpExtender.getStderr().println("关闭数据库连接时发生错误: ");
            ex.printStackTrace(BurpExtender.getStderr());
        }
    }

    public synchronized int insertOrUpdateRequestResponse(String url, byte[] request, byte[] response) {
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String checkSql = "SELECT id FROM requests_response WHERE url = ?";

        try (Connection conn = this.connect();
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            // 检查记录是否存在
            checkStmt.setString(1, url);
            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                // 记录存在，更新记录
                generatedId = rs.getInt("id");
                String updateSql = "UPDATE requests_response SET request = ?, response = ? WHERE id = ?";
                try (PreparedStatement updateStmt = conn.prepareStatement(updateSql)) {
                    updateStmt.setBytes(1, request);
                    updateStmt.setBytes(2, response);
                    updateStmt.setInt(3, generatedId);
                    updateStmt.executeUpdate();
                }
            } else {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO requests_response(url, request, response) VALUES(?, ?, ?)";
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    insertStmt.setString(1, url);
                    insertStmt.setBytes(2, request);
                    insertStmt.setBytes(3, response);
                    insertStmt.executeUpdate();

                    // 获取生成的键值
                    try (ResultSet generatedKeys = insertStmt.getGeneratedKeys()) {
                        if (generatedKeys.next()) {
                            generatedId = generatedKeys.getInt(1); // 获取生成的ID
                        }
                    }
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error inserting or updating requests_response table: ");
            e.printStackTrace(BurpExtender.getStderr());
        }

        return generatedId; // 返回ID值，无论是更新还是插入
    }

    public synchronized Map<String, byte[]> selectRequestResponseById(int id) {
        String sql = "SELECT * FROM requests_response WHERE id = ?";
        Map<String, byte[]> requestResponse = null;

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, id);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    requestResponse = new HashMap<>();
                    requestResponse.put("request", rs.getBytes("request"));
                    requestResponse.put("response", rs.getBytes("response"));
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error selecting from requests_response table by ID: " + id);
            e.printStackTrace(BurpExtender.getStderr());
        }
        return requestResponse;
    }

}

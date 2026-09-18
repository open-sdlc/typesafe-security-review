package com.security.demo;

import java.io.*;
import java.net.URL;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Random;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * WARNING: This class is PURPOSELY VULNERABLE.
 * Do not deploy this code to production or internet-facing servers.
 */
public class VulnerableBankApp {

    // 1. HARDCODED CREDENTIALS (CWE-798)
    private static final String DB_USER = "admin";
    private static final String DB_PASS = "SuperSecretP@ssword123!"; 

    public void processUserRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        
        String input = request.getParameter("userInput");
        String filepath = request.getParameter("file");
        String targetUrl = request.getParameter("url");

        // 2. SQL INJECTION (CWE-89)
        // Concatenating untrusted user input directly into a database query string.
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/bank", DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE username = '" + input + "'"; 
        stmt.executeQuery(sql);

        // 3. COMMAND INJECTION (CWE-78)
        // Passing unvalidated input straight into the runtime environment system shell.
        Runtime.getRuntime().exec("ping -c 1 " + input);

        // 4. PATH TRAVERSAL / ARBITRARY FILE READ (CWE-22)
        // No validation ensures that input doesn't contain path sequences like "../../etc/passwd".
        File file = new File("/var/www/uploads/" + filepath);
        BufferedReader br = new BufferedReader(new FileReader(file));
        
        // 5. REFLECTED CROSS-SITE SCRIPTING / XSS (CWE-79)
        // Untrusted data is echoed right back to the HTTP response without escaping.
        response.getWriter().println("<h1>Welcome back, " + input + "!</h1>");

        // 6. SERVER-SIDE REQUEST FORGERY / SSRF (CWE-918)
        // The server establishes an internal connection to an arbitrary URL supplied by the client.
        URL url = new URL(targetUrl);
        InputStream is = url.openStream();
    }

    // 7. INSECURE DESERIALIZATION (CWE-502)
    // Instantiating objects directly from untrusted byte streams can lead to Remote Code Execution (RCE).
    public Object deserializeData(byte[] bytes) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        ObjectInputStream ois = new ObjectInputStream(bais);
        return ois.readObject(); 
    }

    // 8. USE OF A CRYPTOGRAPHICALLY WEAK PSEUDORANDOM NUMBER GENERATOR / PRNG (CWE-338)
    // java.util.Random is completely predictable and should never be used for security tokens or salts.
    public String generateSessionToken() {
        Random random = new Random();
        return Long.toHexString(random.nextLong());
    }
}
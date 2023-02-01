package io.jenkins.plugins.sample;

import hudson.Launcher;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.util.FormValidation;
import hudson.model.AbstractProject;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.Builder;
import hudson.tasks.BuildStepDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import javax.servlet.ServletException;
import java.io.IOException;
import jenkins.tasks.SimpleBuildStep;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundSetter;

//-

import java.io.File;
import okhttp3.*;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.MultipartBody;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.Timer;
import java.util.TimerTask;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.Run;
import hudson.model.AbstractBuild;
import java.util.HashMap;
import java.util.ArrayList;
import hudson.AbortException;
import hudson.model.Result;
import java.util.Base64;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.Map;
import java.util.List;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.json.JSONObject;
import org.json.JSONArray;
import java.util.StringTokenizer;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import jenkins.model.Jenkins;
import hudson.model.Job;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonObject;



public class CodeThreatBuilder extends Builder implements SimpleBuildStep {

    private final String username;
    private final String password;
    private final String ctServer;
    private final File file;
    private Integer max_number_of_critical;
    private Integer max_number_of_high;
    private String access_token;
    private String scanId;
    private String scanStatus;
    private final String weakness_is;
    private String condition;
    private final String project_name;
    private String title="";
    private String severity="";

    @DataBoundConstructor
    public CodeThreatBuilder(String username, String password, String ctServer, File file, Integer max_number_of_critical, Integer max_number_of_high, String weakness_is, String condition, String project_name ) throws IOException {
        this.username = username;
        this.password = password;
        this.ctServer = ctServer;
        this.file = file;
        this.project_name = project_name;
        this.max_number_of_critical = max_number_of_critical;
        this.max_number_of_high = max_number_of_high;

        this.access_token = getToken();

        if (this.access_token != null) {
            this.scanId = uploadFile();
        }

        if (this.scanId != null) {
            this.scanStatus = awaitScan();
        }

        if(weakness_is == null)
            this.weakness_is = "";
        else
            this.weakness_is = weakness_is;

        if(condition == null)
            this.condition = "AND";
        else
            this.condition = condition;

    }

    public String getName() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getCtServer() {
        return ctServer;
    }

    public File getZipFile() {
        return file;
    }

    public String getAccess_token() {
        return access_token;
    }

    public String getScanId() {
        return scanId;
    }

    public String getScanStatus() {
        return scanStatus;
    }

    public Integer getMaxNumberOfCritical() {
        return max_number_of_critical;
    }

    public Integer getMaxNumberOfHigh() {
        return max_number_of_high;
    }

    public String getWeaknessIs() {
        return weakness_is;
    }

    public String getCondition() {
        return condition;
    }

    public String getProjectName() {
        return project_name;
    }

    public String getTitle() {
        return title;
    }

    public String getSeverity() {
        return severity;
    }

    public String getToken() throws IOException {

        OkHttpClient client = new OkHttpClient();
        MediaType mediaType = MediaType.parse("application/json");
        JSONObject json = new JSONObject();
        json.put("client_id", username);
        json.put("client_secret", password);
        RequestBody body = RequestBody.create(mediaType, json.toString());
        Request request = new Request.Builder()
            .url(ctServer+"api/signin")
            .post(body)
            .build();
        Response response = client.newCall(request).execute();
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode = mapper.readValue(response.body().string(), JsonNode.class);
        access_token = jsonNode.get("access_token").asText();
        return access_token;
    }
    
    public String uploadFile() throws IOException {

        // String pname = "DENEMEJENKINS";
        OkHttpClient client = new OkHttpClient();
        MediaType mediaType = MediaType.parse("application/zip");
        RequestBody fileBody = RequestBody.create(mediaType, file);
        MultipartBody.Builder builder = new MultipartBody.Builder().setType(MultipartBody.FORM);
        builder.addFormDataPart("upfile", "deneme.zip", fileBody);
        builder.addFormDataPart("project", project_name);
        builder.addFormDataPart("from", "jenkins");
        RequestBody requestBody = builder.build();

        Request request = new Request.Builder()
                .url(ctServer+"api/scan/start")
                .post(requestBody)
                .addHeader("Authorization", "Bearer " + access_token)
                .addHeader("x-ct-organization", "codethreat")
                .build();
        Response response = client.newCall(request).execute();
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode = mapper.readValue(response.body().string(), JsonNode.class);
        scanId = jsonNode.get("scan_id").asText();
        return scanId;
    }

    public String awaitScan() throws IOException {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url(ctServer+"api/scan/status/"+scanId)
            .get()
            .addHeader("Authorization", "Bearer " + access_token)
            .addHeader("x-ct-organization", "codethreat")
            .build();
            Response response = client.newCall(request).execute();
            scanStatus = response.body().string();
            return scanStatus;
    }

    public static String convertToHHMMSS(Integer endedAt, Integer startedAt) {

        int durationInMilliseconds = endedAt - startedAt;
        int durationInMinutes = durationInMilliseconds / (1000 * 60);
        int hours = durationInMinutes / 60;
        int minutes = durationInMinutes % 60;
        int seconds = (durationInMilliseconds % (1000 * 60)) / 1000;
        return String.format("%02d:%02d:%02d", hours, minutes, seconds);
    }

    public static String getScore(Integer percentage) {
        ArrayList<HashMap<String, Object>> scores = new ArrayList<>();
        HashMap<String, Object> score;

        score = new HashMap<>();
        score.put("score", "A+");
        score.put("startingPerc", 97);
        score.put("endingPerc", 100);
        scores.add(score);

        score = new HashMap<>();
        score.put("score", "A");
        score.put("startingPerc", 93);
        score.put("endingPerc", 96);
        scores.add(score);

        score = new HashMap<>();
        score.put("score", "A-");
        score.put("startingPerc", 90);
        score.put("endingPerc", 92);
        scores.add(score);
        
        score = new HashMap<>();
        score.put("score", "B+");
        score.put("startingPerc", 87);
        score.put("endingPerc", 89);
        scores.add(score);
        
        score = new HashMap<>();
        score.put("score", "B");
        score.put("startingPerc", 83);
        score.put("endingPerc", 86);
        scores.add(score);
        
        score = new HashMap<>();
        score.put("score", "B-");
        score.put("startingPerc", 80);
        score.put("endingPerc", 82);
        scores.add(score);
        
        score = new HashMap<>();
        score.put("score", "C+");
        score.put("startingPerc", 77);
        score.put("endingPerc", 79);
        scores.add(score);
        
        score = new HashMap<>();
        score.put("score", "C");
        score.put("startingPerc", 73);
        score.put("endingPerc", 76);
        scores.add(score);
        
        score = new HashMap<>();
        score.put("score", "C-");
        score.put("startingPerc", 90);
        score.put("endingPerc", 92);
        scores.add(score);
        
        score = new HashMap<>();
        score.put("score", "D+");
        score.put("startingPerc", 70);
        score.put("endingPerc", 72);
        scores.add(score);
        
        score = new HashMap<>();
        score.put("score", "D");
        score.put("startingPerc", 67);
        score.put("endingPerc", 69);
        scores.add(score);
        
        score = new HashMap<>();
        score.put("score", "D-");
        score.put("startingPerc", 63);
        score.put("endingPerc", 60);
        scores.add(score);
        
        score = new HashMap<>();
        score.put("score", "C-");
        score.put("startingPerc", 60);
        score.put("endingPerc", 62);
        scores.add(score);
        
        score = new HashMap<>();
        score.put("score", "F");
        score.put("startingPerc", 0);
        score.put("endingPerc", 59);
        scores.add(score);
        
        for (int i = 0; i < scores.size(); i++) {
            HashMap<String, Object> score1 = scores.get(i);
            int startingPerc = (int) score1.get("startingPerc");
            int endingPerc = (int) score1.get("endingPerc");

            if (percentage >= startingPerc && percentage <= endingPerc) {
                return score1.get("score").toString();
            }
        }
        return null;
    }

    public String[] newIssue() throws IOException {

        // String projectName = "DENEMEJENKINS";
        JSONArray historical = new JSONArray();
        historical.put("New Issue");

        JSONObject query = new JSONObject();
        query.put("projectName", project_name);
        query.put("historical", historical);

        String jsonString = query.toString();
        byte[] jsonBytes = jsonString.getBytes(StandardCharsets.UTF_8);
        String encodedQ = Base64.getEncoder().encodeToString(jsonBytes);

        
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url(ctServer+"api/scanlog/issues?q="+encodedQ+"&pageSize=500")
            .get()
            .addHeader("Authorization", "Bearer " + access_token)
            .addHeader("x-ct-organization", "codethreat")
            .build();
        Response response = client.newCall(request).execute();
        Headers headers = response.headers();
        // String jsonString1 = new String(Base64.getDecoder().decode(headers.get("x-ct-pager").getBytes()));
        byte[] headerBytes = headers.get("x-ct-pager").getBytes(StandardCharsets.UTF_8);
        String jsonString1 = new String(Base64.getDecoder().decode(headerBytes), StandardCharsets.UTF_8);
        JSONObject xCtPager = new JSONObject(jsonString1);

        int pages = xCtPager.getInt("pages");
        String pid = xCtPager.getString("id");

        String[] extractedArray = new String[0];
            for (int i = 1; i <= pages; i++) {
                Request newRequest = new Request.Builder()
                    .url(ctServer+"api/scanlog/issues?q=" + encodedQ + "&pid=" + pid + "&page=" + i)
                    .get()
                    .addHeader("Authorization", "Bearer " + access_token)
                    .addHeader("x-ct-organization", "codethreat")
                    .build();
                Response newResponse = client.newCall(newRequest).execute();
                JSONArray responseArray = new JSONArray(newResponse.body().string());
                extractedArray = new String[responseArray.length()];

                for (int j = 0; j < responseArray.length(); j++) {
                    JSONObject item = responseArray.getJSONObject(j);
                    extractedArray[j] = item.toString();
                }
            }
                return extractedArray;
    }

    public String[] allIssue() throws IOException {

        // String projectName = "DENEMEJENKINS";

        JSONObject query = new JSONObject();
        query.put("projectName", project_name);

        String jsonString = query.toString();
        byte[] jsonBytes = jsonString.getBytes(StandardCharsets.UTF_8);
        String encodedQ = Base64.getEncoder().encodeToString(jsonBytes);
        
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url(ctServer+"api/scanlog/issues?q="+encodedQ+"&pageSize=500")
            .get()
            .addHeader("Authorization", "Bearer " + access_token)
            .addHeader("x-ct-organization", "codethreat")
            .build();
        Response response = client.newCall(request).execute();
        Headers headers = response.headers();
        byte[] headerBytes = headers.get("x-ct-pager").getBytes(StandardCharsets.UTF_8);
        String jsonString1 = new String(Base64.getDecoder().decode(headerBytes), StandardCharsets.UTF_8);
        JSONObject xCtPager = new JSONObject(jsonString1);

        int pages = xCtPager.getInt("pages");
        String pid = xCtPager.getString("id");

        //String[] allData = {};
        // ArrayList<String> result = new ArrayList<>();
        String[] extractedArray = new String[0];
            for (int i = 1; i <= pages; i++) {
                Request newRequest = new Request.Builder()
                    .url(ctServer+"api/scanlog/issues?q=" + encodedQ + "&pid=" + pid + "&page=" + i)
                    .get()
                    .addHeader("Authorization", "Bearer " + access_token)
                    .addHeader("x-ct-organization", "codethreat")
                    .build();
                Response newResponse = client.newCall(newRequest).execute();
                JSONArray responseArray = new JSONArray(newResponse.body().string());
                extractedArray = new String[responseArray.length()];

                for (int j = 0; j < responseArray.length(); j++) {
                    JSONObject item = responseArray.getJSONObject(j);
                    extractedArray[j] = item.toString();
                }
            }
                return extractedArray;
    }
    
    public static ArrayList<String> findWeaknessTitles(String[] arr, String[] keywords) {
       
        ArrayList<String> failedWeaknesss = new ArrayList<>();
        for (String element : arr) {
            JsonElement jsonElement = new JsonParser().parse(element);
            JsonObject issueState = jsonElement.getAsJsonObject().get("issue_state").getAsJsonObject();
            String weaknessId = issueState.get("weakness_id").getAsString();
            for (String keyword : keywords) {
                if (weaknessId.matches(keyword)) {
                    failedWeaknesss.add(weaknessId);
                    break;
                }
            }
        }
        return failedWeaknesss;
    }

    public List<Map<String, Object>> countAndGroupByTitle(String[] array1) {
        List<Map<String, Object>> nullArr = new ArrayList<Map<String, Object>>();
        if(array1 == null || array1.length == 0){
            return nullArr;
        }

        List<Map<String, Object>> array = new ArrayList<Map<String, Object>>();
        for (String item : array1) {
            Map<String, Object> map = new HashMap<String, Object>();
            map.put("title", item);
            array.add(map);
        }

        Map<String, Integer> titleCounts = new HashMap<String, Integer>();
        Map<String, String> titleSeverity = new HashMap<String, String>();
        for (Map<String, Object> item : array) {
            Map<String, Map<String, String>> kbFields = (Map<String, Map<String, String>>) item.get("kb_fields");
            String title = kbFields.get("title").get("en");
            String severity = (String) ((Map<String, Object>) item.get("issue_state")).get("severity");
            if (!titleCounts.containsKey(title)) {
                titleCounts.put(title, 0);
                titleSeverity.put(title,severity);
            }
            titleCounts.put(title, titleCounts.get(title) + 1);
        }

        List<Map<String, Object>> result = new ArrayList<Map<String, Object>>();
        for (Map.Entry<String, Integer> entry : titleCounts.entrySet()) {
            Map<String, Object> item = new HashMap<String, Object>();
            item.put("title", title);
            item.put("count", titleCounts.get(title));
            item.put("severity", titleSeverity.get(title));
            result.add(item);
        }

       return result;
    }

    public static List<Map<String, Object>> groupAndCount(String[] arr) {   
        Map<String, Map<String, Object>> map = new HashMap<>();
        for (String str : arr) {
        Map<String, Object> json = new Gson().fromJson(str, Map.class);
        Map<String, Object> issueState = (Map<String, Object>) json.get("issue_state");
        Map<String, Object> kbFields = (Map<String, Object>) json.get("kb_fields");
        String title = ((Map<String, String>) kbFields.get("title")).get("en");
        String severity = (String) issueState.get("severity");
        if (map.containsKey(title)) {
        Map<String, Object> stored = map.get(title);
        int count = (int) stored.get("count");
        stored.put("count", count + 1);
        } else {
        Map<String, Object> stored = new HashMap<>();
        stored.put("title", title);
        stored.put("count", 1);
        stored.put("severity", severity);
        map.put(title, stored);
        }
        }
        return new ArrayList<>(map.values());
    }

    public static List<Map<String, Object>> groupIssues(String[] arr) {
        Map<String, Integer> titleCount = new HashMap<>();
        Map<String, String> titleSeverity = new HashMap<>();
        List<Map<String, Object>> result = new ArrayList<>();

        for (String issue : arr) {
            Map<String, Object> issueJson = new Gson().fromJson(issue, new TypeToken<Map<String, Object>>(){}.getType());
            Map<String, Object> issueState = (Map<String, Object>) issueJson.get("issue_state");
            Map<String, Object> kbFields = (Map<String, Object>) issueJson.get("kb_fields");
            Map<String, Object> title = (Map<String, Object>) kbFields.get("title");
            String titleEn = (String) title.get("en");

            if (titleCount.containsKey(titleEn)) {
                titleCount.put(titleEn, titleCount.get(titleEn) + 1);
            } else {
                titleCount.put(titleEn, 1);
            }

            titleSeverity.put(titleEn, (String) issueState.get("severity"));
        }

        for (Map.Entry<String, Integer> entry : titleCount.entrySet()) {
            Map<String, Object> groupedIssue = new HashMap<>();
            groupedIssue.put("title", entry.getKey());
            groupedIssue.put("count", entry.getValue());
            groupedIssue.put("severity", titleSeverity.get(entry.getKey()));
            result.add(groupedIssue);
        }

        return result;
    }

    private static Map<String, Object> parseJson(String json) {
        Map<String, Object> map = new HashMap<>();
        Pattern pattern = Pattern.compile("\"(.*?)\":\\s*\"(.*?)\"");
        Matcher matcher = pattern.matcher(json);

        while (matcher.find()) {
            String key = matcher.group(1);
            String value = matcher.group(2);
            if (key.equals("title")) {
                value = value.split("en\":")[1].split("\",")[0].replace("\"", "");
            }
            if (key.equals("severity")) {
                value = value.replace("\"", "");
            }
            map.put(key, value);
        }

        return map;
    }

    public static Map<String, Integer> countSeverity(List<Map<String, Object>> list) {
        Map<String, Integer> result = new HashMap<>();
        result.put("critical", 0);
        result.put("high", 0);
        result.put("medium", 0);
        result.put("low", 0);
        for (Map<String, Object> item : list) {
            String severity = (String) item.get("severity");
            int count = (int) item.get("count");
            result.put(severity, result.get(severity) + count);
        }
        return result;
    }

    @Override
    public void perform(Run<?, ?> run, FilePath workspace, EnvVars env, Launcher launcher, TaskListener listener) throws InterruptedException, IOException, AbortException {

            listener.getLogger().println(" ---> SCAN STARTED!");
            while(true){
                ObjectMapper mapper = new ObjectMapper();
                JsonNode jsonNode = mapper.readValue(scanStatus, JsonNode.class);
                Integer critical = jsonNode.get("severities").get("critical") != null ? jsonNode.get("severities").get("critical").asInt() : 0;
                Integer high = jsonNode.get("severities").get("high") != null ? jsonNode.get("severities").get("high").asInt() : 0;
                Integer medium = jsonNode.get("severities").get("medium") != null ? jsonNode.get("severities").get("medium").asInt() : 0;
                Integer low = jsonNode.get("severities").get("low") != null ? jsonNode.get("severities").get("low").asInt() : 0;
                if (jsonNode.get("state").asText().equals("end")) {
                    listener.getLogger().println("- Scan completed successfuly - ");
                    listener.getLogger().println("------------- SCAN STATUS (END) "+"(%"+jsonNode.get("progress_data").get("progress").asInt()+")"+" -------------");
                    listener.getLogger().println("- Critical --> " + critical);
                    listener.getLogger().println("- High --> " + high);
                    listener.getLogger().println("- Medium --> " + medium);
                    listener.getLogger().println("- Low --> " + low);
                    listener.getLogger().println("Scan Duration --> "+convertToHHMMSS(jsonNode.get("ended_at").asInt(),jsonNode.get("started_at").asInt()));
                    listener.getLogger().println("Risk Score --> "+getScore(jsonNode.get("riskscore").asInt()));

                    String[] weaknessArr = weakness_is.split(",");
                    ArrayList<String> weaknessIsCount = findWeaknessTitles(allIssue(), weaknessArr);
                    
                    List<Map<String,Object>> newIssuesData = groupIssues(newIssue());
                    Map<String, Integer> newIssuesSeverity = countSeverity(newIssuesData);
                    List<Map<String,Object>> allIssuesData = groupIssues(allIssue());
                    int totalCountNewIssues = 0;
                    for (Map<String, Object> obj : newIssuesData) {
                    totalCountNewIssues += (Integer) obj.get("count");
                    }

                    String html = "<html>\n" +
                                "  <head>\n" +
                                "  <title>Report</title>\n";

                    StringBuilder style = new StringBuilder("<style>table{border-collapse: collapse;} th, td {border: 1px solid black;padding: 8px;text-align: center;vertical-align: middle;}th {background-color: white;}tr:nth-child(even) td {background-color: lightgray;}ul {list-style-type: none;padding: 0;margin: 0;}li {padding: 8px;color: blue;}a {color: #4169E1;text-decoration: none;}</style>\n");
                    html += style;
                    html +=  "  </head>\n" +
                             "  <body style='font-family:helvetica'>\n";
                               
                    html += "<h2>Result</h2>";

                    String table = "<table >";
                    table += "<tr><th >Weakness</th><th >Total Issue</th><th >New Issue</th></tr>";

                    StringBuilder trCritical = new StringBuilder("<tr>\n");
                    trCritical.append("  <td ><em>").append("🔴 Critical").append("</em></td>\n");
                    trCritical.append("  <td >").append(critical).append("</td>\n");
                    trCritical.append("  <td >").append(newIssuesSeverity.get("critical")).append("</td>\n");
                    trCritical.append("</tr>");

                    StringBuilder trHigh = new StringBuilder("<tr>\n");
                    trHigh.append("  <td ><em>").append("🟠 High").append("</em></td>\n");
                    trHigh.append("  <td >").append(high).append("</td>\n");
                    trHigh.append("  <td >").append(newIssuesSeverity.get("high")).append("</td>\n");
                    trHigh.append("</tr>");

                    StringBuilder trMedium = new StringBuilder("<tr>\n");
                    trMedium.append("  <td ><em>").append("🟡 Medium").append("</em></td>\n");
                    trMedium.append("  <td >").append(medium).append("</td>\n");
                    trMedium.append("  <td >").append(newIssuesSeverity.get("medium")).append("</td>\n");
                    trMedium.append("</tr>");

                    StringBuilder trLow = new StringBuilder("<tr>\n");
                    trLow.append("  <td ><em>").append("🔵 Low").append("</em></td>\n");
                    trLow.append("  <td >").append(low).append("</td>\n");
                    trLow.append("  <td >").append(newIssuesSeverity.get("low")).append("</td>\n");
                    trLow.append("</tr>");

                    int total = 0;
                    JsonNode severities = jsonNode.get("severities");
                    for (JsonNode severity : severities) {
                        total += severity.asInt();
                    }

                    StringBuilder trTotal = new StringBuilder("<tr>\n");
                    trTotal.append("  <td ><em>").append("🔘 TOTAL").append("</em></td>\n");
                    trTotal.append("  <td >").append(total).append("</td>\n");
                    trTotal.append("  <td >").append(totalCountNewIssues).append("</td>\n");
                    trTotal.append("</tr>");

                    table += trCritical;
                    table += trHigh;
                    table += trMedium;
                    table += trLow;
                    table += trTotal;

                    html += table;
                    html += "</table>";

                    html += "<h2>Weaknesses</h2>";

                    StringBuilder weaknessListUl = new StringBuilder("<ul >");
                    html += weaknessListUl;
                    StringBuilder weaknessList = new StringBuilder("");

                    for (Map<String, Object> item : allIssuesData) {
                    JSONObject query = new JSONObject();
                    query.put("projectName", project_name);
                    query.put("issuename", item.get("title"));

                    String jsonString = query.toString();
                    byte[] jsonBytes = jsonString.getBytes(StandardCharsets.UTF_8);
                    String encodedQ = Base64.getEncoder().encodeToString(jsonBytes);

                    StringBuilder weaknessLi = new StringBuilder("<li>\n");
                    StringBuilder weaknessA = new StringBuilder("<a href='\n");
                    weaknessA.append(ctServer+"issues?q="+encodedQ);
                    weaknessA.append("'>");
                    weaknessA.append(item.get("title"));
                    weaknessA.append(" --> (");
                    weaknessA.append(item.get("count"));
                    weaknessA.append(")");
                    weaknessA.append("</a>");
                    weaknessLi.append(weaknessA);
                    weaknessLi.append("</li>");
                    weaknessList.append(weaknessLi);
                    }
                    html += weaknessList;
                    html += "</ul>";

                    html += "<p>⏳ Scan Duration: "+convertToHHMMSS(jsonNode.get("ended_at").asInt(),jsonNode.get("started_at").asInt())+"</p>";
                    html += "<p>❗ Risk Score: -> "+getScore(jsonNode.get("riskscore").asInt())+"</p>";

                    html += "  </body>\n" +
                    "</html>";

                if(condition == "OR"){
                        if(max_number_of_critical != null && critical > max_number_of_critical){
                            run.addAction(new CodeThreatAction(html));
                            throw new AbortException(" ---> Critical limit exceeded");
                        }
                        if(max_number_of_high != null && high > max_number_of_high){
                            run.addAction(new CodeThreatAction(html));
                            throw new AbortException(" ---> High limit exceeded");
                        }
                        if(weaknessIsCount.size() > 0){
                            run.addAction(new CodeThreatAction(html));
                            throw new AbortException(" ---> Weaknesses entered in the weakness_is key were found during the scan.");
                        }
                    } else if(condition == "AND"){
                        if((max_number_of_critical != null && critical > max_number_of_critical) || (max_number_of_high != null && high > max_number_of_high) ||  weaknessIsCount.size() > 0){
                            run.addAction(new CodeThreatAction(html));
                            throw new AbortException(" ---> Not all conditions are met according to the given arguments");
                        }
                    }

                run.addAction(new CodeThreatAction(html));
                    break;
                } else {
                    listener.getLogger().println("------------- SCAN STATUS "+"(%"+jsonNode.get("progress_data").get("progress").asInt()+")"+" -------------");
                    listener.getLogger().println("- Critical --> " + critical);
                    listener.getLogger().println("- High --> " + high);
                    listener.getLogger().println("- Medium --> " + medium);
                    listener.getLogger().println("- Low --> " + low);
                    Thread.sleep(3000);
                    awaitScan();
                }
            }
    }

    @Symbol("CodeThreatScan")
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return "CodeThreat";
        }

    }

}

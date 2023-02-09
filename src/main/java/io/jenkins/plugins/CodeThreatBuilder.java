package io.jenkins.plugins;

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


import hudson.util.Secret;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import hudson.security.ACL;


import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import javax.annotation.Nonnull;
import java.io.File;
import java.util.regex.Pattern;


public class CodeThreatBuilder extends Builder implements SimpleBuildStep {

    private final String ctServer;
    private Integer max_number_of_critical;
    private Integer max_number_of_high;
    private String scanId;
    private String scanStatus;
    private final String weakness_is;
    private String condition;
    private final String project_name;
    private String title="";
    private String severity="";

    private Secret password;
    private String username;
    private Secret accessTokenSecret;
    private String fileName;
    private String credentialsId;

    @DataBoundConstructor
    public CodeThreatBuilder(String ctServer, Integer max_number_of_critical, Integer max_number_of_high, String weakness_is, String condition, String project_name, String fileName, String credentialsId ) throws IOException {
        this.ctServer = ctServer;
        this.fileName = fileName;
        this.project_name = project_name;
        this.max_number_of_critical = max_number_of_critical;
        this.max_number_of_high = max_number_of_high;
        this.credentialsId = credentialsId;

        if(weakness_is == null)
            this.weakness_is = "";
        else
            this.weakness_is = weakness_is;

        if(condition == null)
            this.condition = "AND";
        else
            this.condition = condition;

    }

    public String getCtServer() {
        return ctServer;
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

    public Secret getToken(String username, Secret password) throws IOException {

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
         if (!response.isSuccessful())
            throw new IOException("Unexpected code " + response);

        ResponseBody body1 = response.body();
        if (body1 == null)
            throw new IOException("Unexpected body to be null");

        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode = mapper.readValue(body1.string(), JsonNode.class);
        return Secret.fromString(jsonNode.get("access_token").asText());
    }
    
    public String uploadFile(Secret accessTokenSecret, File fullFile) throws IOException {

        OkHttpClient client = new OkHttpClient();
        MediaType mediaType = MediaType.parse("application/zip");
        RequestBody fileBody = RequestBody.create(mediaType, fullFile);
        MultipartBody.Builder builder = new MultipartBody.Builder().setType(MultipartBody.FORM);
        builder.addFormDataPart("upfile", project_name+".zip", fileBody);
        builder.addFormDataPart("project", project_name);
        builder.addFormDataPart("from", "jenkins");
        RequestBody requestBody = builder.build();

        Request request = new Request.Builder()
                .url(ctServer+"api/scan/start")
                .post(requestBody)
                .addHeader("Authorization", "Bearer " + accessTokenSecret)
                .addHeader("x-ct-organization", "codethreat")
                .build();
        Response response = client.newCall(request).execute();
        if (!response.isSuccessful())
            throw new IOException("Unexpected code " + response);

        ResponseBody body1 = response.body();
        if (body1 == null)
            throw new IOException("Unexpected body to be null");
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode = mapper.readValue(body1.string(), JsonNode.class);
        return jsonNode.get("scan_id").asText();
    }

    public String awaitScan(String scanId, Secret accessTokenSecret) throws IOException {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url(ctServer+"api/scan/status/"+scanId)
            .get()
            .addHeader("Authorization", "Bearer " + accessTokenSecret)
            .addHeader("x-ct-organization", "codethreat")
            .build();
            Response response = client.newCall(request).execute();
            if (!response.isSuccessful())
            throw new IOException("Unexpected code " + response);

            ResponseBody body1 = response.body();
            if (body1 == null)
                throw new IOException("Unexpected body to be null");
            return body1.string();
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

    public String[] newIssue(Secret accessTokenSecret) throws IOException {

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
            .addHeader("Authorization", "Bearer " + accessTokenSecret)
            .addHeader("x-ct-organization", "codethreat")
            .build();
        Response response = client.newCall(request).execute();
        if (!response.isSuccessful())
            throw new IOException("Unexpected code " + response);

        String headers = response.headers().get("x-ct-pager");
        if (headers == null)
            throw new IOException("Unexpected body to be null");
        byte[] headerBytes = headers.getBytes(StandardCharsets.UTF_8);
        String jsonString1 = new String(Base64.getDecoder().decode(headerBytes), StandardCharsets.UTF_8);
        JSONObject xCtPager = new JSONObject(jsonString1);

        int pages = xCtPager.getInt("pages");
        String pid = xCtPager.getString("id");

        String[] extractedArray = new String[0];
            for (int i = 1; i <= pages; i++) {
                Request newRequest = new Request.Builder()
                    .url(ctServer+"api/scanlog/issues?q=" + encodedQ + "&pid=" + pid + "&page=" + i)
                    .get()
                    .addHeader("Authorization", "Bearer " + accessTokenSecret)
                    .addHeader("x-ct-organization", "codethreat")
                    .build();
                Response newResponse = client.newCall(newRequest).execute();
                if (!response.isSuccessful())
                    throw new IOException("Unexpected code " + response);

                ResponseBody body1 = response.body();
                if (body1 == null)
                    throw new IOException("Unexpected body to be null");
                JSONArray responseArray = new JSONArray(body1.string());
                extractedArray = new String[responseArray.length()];

                for (int j = 0; j < responseArray.length(); j++) {
                    JSONObject item = responseArray.getJSONObject(j);
                    extractedArray[j] = item.toString();
                }
            }
                return extractedArray;
    }

    public String[] allIssue(Secret accessTokenSecret) throws IOException {

        JSONObject query = new JSONObject();
        query.put("projectName", project_name);

        String jsonString = query.toString();
        byte[] jsonBytes = jsonString.getBytes(StandardCharsets.UTF_8);
        String encodedQ = Base64.getEncoder().encodeToString(jsonBytes);
        
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url(ctServer+"api/scanlog/issues?q="+encodedQ+"&pageSize=500")
            .get()
            .addHeader("Authorization", "Bearer " + accessTokenSecret)
            .addHeader("x-ct-organization", "codethreat")
            .build();
        Response response = client.newCall(request).execute();
        if (!response.isSuccessful())
                    throw new IOException("Unexpected code " + response);

        String headers = response.headers().get("x-ct-pager");
        if (headers == null)
            throw new IOException("Unexpected body to be null");
        byte[] headerBytes = headers.getBytes(StandardCharsets.UTF_8);
        String jsonString1 = new String(Base64.getDecoder().decode(headerBytes), StandardCharsets.UTF_8);
        JSONObject xCtPager = new JSONObject(jsonString1);

        int pages = xCtPager.getInt("pages");
        String pid = xCtPager.getString("id");

        String[] extractedArray = new String[0];
            for (int i = 1; i <= pages; i++) {
                Request newRequest = new Request.Builder()
                    .url(ctServer+"api/scanlog/issues?q=" + encodedQ + "&pid=" + pid + "&page=" + i)
                    .get()
                    .addHeader("Authorization", "Bearer " + accessTokenSecret)
                    .addHeader("x-ct-organization", "codethreat")
                    .build();
                Response newResponse = client.newCall(newRequest).execute();
                if (!response.isSuccessful())
                    throw new IOException("Unexpected code " + response);

                ResponseBody body1 = response.body();
                if (body1 == null)
                    throw new IOException("Unexpected body to be null");
                JSONArray responseArray = new JSONArray(body1.string());
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


            List<StandardUsernamePasswordCredentials> credentials = CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class, Jenkins.get(), ACL.SYSTEM, new ArrayList<DomainRequirement>());

            for (StandardUsernamePasswordCredentials cred : credentials) {
                if (cred.getId().equals(credentialsId)) {
                username = cred.getUsername();
                password = cred.getPassword();
                break;
                }
            }

            accessTokenSecret = getToken(username,password);
            String fullFileName = workspace + File.separator + fileName;
            File fullFile = new File(fullFileName);
            
            if (fullFileName.length() > 100) {
                throw new AbortException(" ---> Disallowed file name");
            }
        
            scanId = uploadFile(accessTokenSecret,fullFile);
            scanStatus = awaitScan(scanId,accessTokenSecret);
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
                    ArrayList<String> weaknessIsCount = findWeaknessTitles(allIssue(accessTokenSecret), weaknessArr);
                    
                    List<Map<String,Object>> newIssuesData = groupIssues(newIssue(accessTokenSecret));
                    Map<String, Integer> newIssuesSeverity = countSeverity(newIssuesData);
                    List<Map<String,Object>> allIssuesData = groupIssues(allIssue(accessTokenSecret));
                    int totalCountNewIssues = 0;
                    for (Map<String, Object> obj : newIssuesData) {
                    totalCountNewIssues += (Integer) obj.get("count");
                    }

                    int total = 0;
                    JsonNode severities = jsonNode.get("severities");
                    for (JsonNode severity : severities) {
                        total += severity.asInt();
                    }

                    List<Map<String, Object>> resultList = new ArrayList<>();
                    for (Map<String, Object> item : allIssuesData) {
                        JSONObject query = new JSONObject();
                        query.put("projectName", project_name);
                        query.put("issuename", item.get("title"));

                        String jsonString = query.toString();
                        byte[] jsonBytes = jsonString.getBytes(StandardCharsets.UTF_8);
                        String encodedQ = Base64.getEncoder().encodeToString(jsonBytes);

                        String link = ctServer+"issues?q="+encodedQ;
                        String count = item.get("count").toString();
                        String title = item.get("title").toString();

                        Map<String, Object> result = new HashMap<>();
                        result.put("link", link);
                        result.put("count", count);
                        result.put("title", title);

                        resultList.add(result);
                    }

                    String durationTime = convertToHHMMSS(jsonNode.get("ended_at").asInt(),jsonNode.get("started_at").asInt());
                    String riskScore = getScore(jsonNode.get("riskscore").asInt());

                    if(condition == "OR"){
                        if(max_number_of_critical != null && critical > max_number_of_critical){
                            run.addAction(new CodeThreatAction(critical,high,medium,low,total,totalCountNewIssues,newIssuesSeverity,resultList,durationTime,riskScore));
                            throw new AbortException(" ---> Critical limit exceeded");
                        }
                        if(max_number_of_high != null && high > max_number_of_high){
                            run.addAction(new CodeThreatAction(critical,high,medium,low,total,totalCountNewIssues,newIssuesSeverity,resultList,durationTime,riskScore));
                            throw new AbortException(" ---> High limit exceeded");
                        }
                        if(weaknessIsCount.size() > 0){
                            run.addAction(new CodeThreatAction(critical,high,medium,low,total,totalCountNewIssues,newIssuesSeverity,resultList,durationTime,riskScore));
                            throw new AbortException(" ---> Weaknesses entered in the weakness_is key were found during the scan.");
                        }
                    } else if(condition == "AND"){
                        if((max_number_of_critical != null && critical > max_number_of_critical) || (max_number_of_high != null && high > max_number_of_high) ||  weaknessIsCount.size() > 0){
                            run.addAction(new CodeThreatAction(critical,high,medium,low,total,totalCountNewIssues,newIssuesSeverity,resultList,durationTime,riskScore));
                            throw new AbortException(" ---> Not all conditions are met according to the given arguments");
                        }
                    }

                run.addAction(new CodeThreatAction(critical,high,medium,low,total,totalCountNewIssues,newIssuesSeverity,resultList,durationTime,riskScore));
                    break;
                } else {
                    listener.getLogger().println("------------- SCAN STATUS "+"(%"+jsonNode.get("progress_data").get("progress").asInt()+")"+" -------------");
                    listener.getLogger().println("- Critical --> " + critical);
                    listener.getLogger().println("- High --> " + high);
                    listener.getLogger().println("- Medium --> " + medium);
                    listener.getLogger().println("- Low --> " + low);
                    Thread.sleep(3000);
                    scanStatus = awaitScan(scanId,accessTokenSecret);
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

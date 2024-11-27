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

import org.acegisecurity.Authentication;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundSetter;

//-

import java.io.File;
import okhttp3.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.ArrayList;
import hudson.AbortException;
import java.util.Base64;
import java.util.Map;
import java.util.List;
import com.google.gson.Gson;
import org.json.JSONObject;
import org.json.JSONArray;
import java.nio.charset.StandardCharsets;
import jenkins.model.Jenkins;
import com.google.gson.reflect.TypeToken;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonObject;

import org.jenkinsci.plugins.plaincredentials.StringCredentials;

import hudson.util.Secret;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import hudson.security.ACL;

import com.cloudbees.plugins.credentials.domains.DomainRequirement;

public class CodeThreatBuilder extends Builder implements SimpleBuildStep {

    private final String ctServer;
    private Integer max_number_of_critical;
    private Integer max_number_of_high;
    private Integer sca_max_number_of_critical;
    private Integer sca_max_number_of_high;
    private String scanId;
    private String scanStatus;
    private String report;
    private String weakness_is = "";
    private String condition = "AND";
    private final String project_name;
    private String title = "";
    private String severity = "";

    private Secret password;
    private String username;
    private Secret accessTokenSecret;
    private String fileName;
    private String credentialsId;
    private String organization_name;
    private String policy_name;

    @DataBoundConstructor
    public CodeThreatBuilder(String ctServer, String project_name, String fileName, String credentialsId,
            String organization_name) throws IOException {

        while (ctServer.endsWith("/")) {
            ctServer = ctServer.substring(0, ctServer.length() - 1);
        }
        this.ctServer = ctServer;
        this.fileName = fileName;
        this.project_name = project_name;
        this.credentialsId = credentialsId;
        this.organization_name = organization_name;
    }

    @DataBoundSetter
    public void setMaxNumberOfCritical(Integer max_number_of_critical) {
        this.max_number_of_critical = max_number_of_critical;
    }
    
    @DataBoundSetter
    public void setMaxNumberOfHigh(Integer max_number_of_high) {
        this.max_number_of_high = max_number_of_high;
    }

    @DataBoundSetter
    public void setScaMaxNumberOfCritical(Integer sca_max_number_of_critical) {
        this.sca_max_number_of_critical = sca_max_number_of_critical;
    }

    @DataBoundSetter
    public void setScaMaxNumberOfHigh(Integer sca_max_number_of_high) {
        this.sca_max_number_of_high = sca_max_number_of_high;
    }

    @DataBoundSetter
    public void setWeaknessIs(String weakness_is) {
        this.weakness_is = weakness_is;
    }

    @DataBoundSetter
    public void setCondition(String condition) {
        this.condition = condition;
    }

    @DataBoundSetter
    public void setPolicyName(String policy_name) {
        this.policy_name = policy_name;
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

    public Integer getScaMaxNumberOfCritical() {
        return sca_max_number_of_critical;
    }

    public Integer getScaMaxNumberOfHigh() {
        return sca_max_number_of_high;
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

    public String getPolicyName() {
        return policy_name;
    }

    public Secret getToken(String username, Secret password) throws IOException {

        OkHttpClient client = new OkHttpClient();
        MediaType mediaType = MediaType.parse("application/json");
        JSONObject json = new JSONObject();
        json.put("client_id", username);
        json.put("client_secret", password);
        RequestBody body = RequestBody.create(mediaType, json.toString());
        Request request = new Request.Builder()
                .url(ctServer + "/api/signin")
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
        builder.addFormDataPart("upfile", project_name + ".zip", fileBody);
        builder.addFormDataPart("project", project_name);
        builder.addFormDataPart("from", "jenkins");
        if(policy_name != null){
            builder.addFormDataPart("policy_id", policy_name);
        }
        RequestBody requestBody = builder.build();
        Request request = new Request.Builder()
                .url(ctServer + "/api/plugins/jenkins")
                .post(requestBody)
                .addHeader("Authorization", "Bearer " + accessTokenSecret)
                .addHeader("x-ct-organization", organization_name)
                .addHeader("x-ct-plugin", "jenkins")
                .build();
        Response response = client.newCall(request).execute();
        if (response == null) {
            throw new IOException("Unexpected null response");
        }
        int statusCode = response.code();
        if (!response.isSuccessful()) {
            ResponseBody responseBody = response.body();
            if (responseBody != null) {
                String responseBodyString = responseBody.string();
                if (!responseBodyString.isEmpty()) {
                    ObjectMapper mapper = new ObjectMapper();
                    JsonNode jsonNode = mapper.readTree(responseBodyString);
                    int errorCode = jsonNode.get("code").asInt();
                    String errorMessage = jsonNode.get("message").asText();
                    throw new IOException("Error: " + errorMessage + " (Code: " + errorCode + ")");
                }
            }
            throw new IOException("Unexpected code " + statusCode + " - " + response.message());
        }

        ResponseBody responseBody = response.body();
        if (responseBody == null) {
            throw new IOException("Unexpected null response body");
        }

        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode = mapper.readValue(responseBody.string(), JsonNode.class);
        return jsonNode.get("scan_id").asText();
    }

    public String awaitScan(String scanId, Secret accessTokenSecret) throws IOException {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
                .url(ctServer + "/api/scan/status/" + scanId)
                .get()
                .addHeader("Authorization", "Bearer " + accessTokenSecret)
                .addHeader("x-ct-organization", organization_name)
                .build();
        Response response = client.newCall(request).execute();
        if (!response.isSuccessful())
            throw new IOException("Unexpected code " + response);

        ResponseBody body1 = response.body();
        if (body1 == null)
            throw new IOException("Unexpected body to be null");
        return body1.string();
    }

    public String endStatus(String scanId, Secret accessTokenSecret, String ctServer, String organization_name, String project_name)
            throws IOException {
        String endpointURL = ctServer + "/api/plugins/helper?sid=" + scanId + "&project_name=" + project_name;
        OkHttpClient client = new OkHttpClient();

        Request request = new Request.Builder()
                .url(endpointURL)
                .get()
                .addHeader("Authorization", "Bearer " + accessTokenSecret)
                .addHeader("x-ct-organization", organization_name)
                .addHeader("x-ct-baseURL", ctServer)
                .addHeader("x-ct-from", "jenkins")
                .build();
        Response response = client.newCall(request).execute();
        if (!response.isSuccessful())
            throw new IOException("Unexpected code " + response);

        ResponseBody responseBody = response.body();
        if (responseBody == null) {
            throw new IOException("Unexpected null response body");
        }

        return responseBody.string();
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

    @Override
    public void perform(Run<?, ?> run, FilePath workspace, EnvVars env, Launcher launcher, TaskListener listener)
            throws InterruptedException, IOException, AbortException {

        List<StandardUsernamePasswordCredentials> credentials = CredentialsProvider.lookupCredentials(
                StandardUsernamePasswordCredentials.class, Jenkins.get(), ACL.SYSTEM,
                new ArrayList<DomainRequirement>());

        for (StandardUsernamePasswordCredentials cred : credentials) {
            if (cred.getId().equals(credentialsId)) {
                username = cred.getUsername();
                password = cred.getPassword();
                break;
            }
        }

        if (username != null) {
            accessTokenSecret = getToken(username, password);
        } else {
            List<StringCredentials> stringCredentials = CredentialsProvider.lookupCredentials(StringCredentials.class,
                    Jenkins.get(), ACL.SYSTEM, new ArrayList<DomainRequirement>());

            for (StringCredentials cred : stringCredentials) {
                if (cred.getId().equals(credentialsId)) {
                    accessTokenSecret = cred.getSecret();
                    break;
                }
            }
        }
        String fullFileName = workspace + File.separator + fileName;
        File fullFile = new File(fullFileName);
        String canonicalFilePath = fullFile.getCanonicalPath();

        listener.getLogger().println("------------------------------");
        listener.getLogger().println("CodeThreat Server: " + ctServer);
        listener.getLogger().println("User: " + username);
        listener.getLogger().println("Project: " + project_name);
        listener.getLogger().println("Organization: " + organization_name);
        listener.getLogger().println("------------------------------");

        String replaceString = null;

        if (canonicalFilePath.indexOf("/private") != -1) {
            replaceString = canonicalFilePath.replace("/private", "");
        }

        if (replaceString != null) {
            if (fullFileName.compareTo(replaceString) != 0) {
                throw new AbortException(" ---> Disallowed file name");
            }
        } else {
            if (fullFileName.compareTo(canonicalFilePath) != 0) {
                throw new AbortException(" ---> Disallowed file name");
            }
        }

        scanId = uploadFile(accessTokenSecret, fullFile);
        scanStatus = awaitScan(scanId, accessTokenSecret);
        listener.getLogger().println("[CodeThreat]: Scan Started.");

        while (true) {

            ObjectMapper mapper = new ObjectMapper();
            JsonNode jsonNode = mapper.readValue(scanStatus, JsonNode.class);
            if(jsonNode.get("state").asText().equals("failure")){
                throw new AbortException("[CodeThreat]: Scan Failed.");
            }
            Integer critical = jsonNode.get("sast_severities").get("critical") != null
                    ? jsonNode.get("sast_severities").get("critical").asInt()
                    : 0;
            Integer high = jsonNode.get("sast_severities").get("high") != null
                    ? jsonNode.get("sast_severities").get("high").asInt()
                    : 0;
            Integer medium = jsonNode.get("sast_severities").get("medium") != null
                    ? jsonNode.get("sast_severities").get("medium").asInt()
                    : 0;
            Integer low = jsonNode.get("sast_severities").get("low") != null ? jsonNode.get("sast_severities").get("low").asInt()
                    : 0;
            JsonNode weaknessesNode = jsonNode.get("weaknessArr");
            String[] weaknessesArr;
            if (weaknessesNode != null && weaknessesNode.isArray()) {
                weaknessesArr = new String[weaknessesNode.size()];
                int i = 0;
                for (JsonNode node : weaknessesNode) {
                    weaknessesArr[i++] = node.asText();
                }
            } else {
                weaknessesArr = new String[0];
            }
            if (jsonNode.get("state").asText().equals("end")) {
                listener.getLogger()
                        .println("[CodeThreat]: Scan completed successfully.");

                report = endStatus(scanId, accessTokenSecret, ctServer, organization_name, project_name);
                JsonNode jsonStatus = mapper.readValue(report, JsonNode.class);
                String resultsLink = ctServer+"/org/"+organization_name+"/projects/project-details/"+project_name+"?branch=noBranch&type=sast";
                String durationTime = jsonStatus.get("report").get("durationTime").asText();
                String riskScore = jsonStatus.get("report").get("riskscore").get("score").asText();
                String fixedIssues = jsonStatus.get("report").get("fixedIssues").asText();
                JsonNode scaDeps = jsonStatus.get("report").get("scaDeps");

                Integer scaCritical = jsonStatus.get("report").get("scaSeverityCounts").get("Critical") != null
                ? jsonStatus.get("report").get("scaSeverityCounts").get("Critical").asInt()
                : 0;
                Integer scaHigh = jsonStatus.get("report").get("scaSeverityCounts").get("High") != null
                ? jsonStatus.get("report").get("scaSeverityCounts").get("High").asInt()
                : 0;

                String[] weaknessArr = weakness_is.split(",");
                ArrayList<String> weaknessIsCount = findWeaknessTitles(weaknessesArr, weaknessArr);

                if (condition == "OR") {
                    if (max_number_of_critical != null && critical > max_number_of_critical) {
                        throw new AbortException(
                                " ---> Critical limit exceeded. [Pipeline interrupted because the FAILED_ARGS arguments you entered were found...]");
                    }
                    if (max_number_of_high != null && high > max_number_of_high) {
                        throw new AbortException(
                                " ---> High limit exceeded. [Pipeline interrupted because the FAILED_ARGS arguments you entered were found...]");
                    }
                    if (weaknessIsCount.size() > 0) {
                        throw new AbortException(
                                " ---> Weaknesses entered in the weakness_is key were found during the scan. [Pipeline interrupted because the FAILED_ARGS arguments you entered were found...]");
                    }
                    if (sca_max_number_of_critical != null && scaCritical > sca_max_number_of_critical) {
                        throw new AbortException(
                                " ---> Sca Critical limit exceeded. [Pipeline interrupted because the FAILED_ARGS arguments you entered were found...]");
                    }
                    if (sca_max_number_of_high != null && scaHigh > sca_max_number_of_high) {
                        throw new AbortException(
                                " ---> Sca High limit exceeded. [Pipeline interrupted because the FAILED_ARGS arguments you entered were found...]");
                    }
                } else if (condition == "AND") {
                    if ((max_number_of_critical != null && critical > max_number_of_critical)
                            || (max_number_of_high != null && high > max_number_of_high)
                            || (sca_max_number_of_critical != null && scaCritical > sca_max_number_of_critical)
                            || (sca_max_number_of_high != null && scaHigh > sca_max_number_of_high)
                            || weaknessIsCount.size() > 0) {
                        throw new AbortException(
                                " ---> Not all conditions are met according to the given arguments. [Pipeline interrupted because the FAILED_ARGS arguments you entered were found...]");
                    }
                }


                run.addAction(new CodeThreatAction(critical, high, medium, low, durationTime, riskScore, resultsLink, report, project_name, fixedIssues, scaDeps));
                break;
            } else {
                listener.getLogger()
                        .println("[CodeThreat]: Scan Status | Scanning...");

                String[] keywords = weakness_is.split(",");
                ArrayList<String> weaknessIsCount = findWeaknessTitles(weaknessesArr, keywords);

                if (condition == "OR") {
                    if (max_number_of_critical != null && critical > max_number_of_critical) {
                        throw new AbortException(
                                " ---> Critical limit exceeded. [Pipeline interrupted because the FAILED_ARGS arguments you entered were found...]");
                    }
                    if (max_number_of_high != null && high > max_number_of_high) {
                        throw new AbortException(
                                " ---> High limit exceeded. [Pipeline interrupted because the FAILED_ARGS arguments you entered were found...]");
                    }
                    if (weaknessIsCount.size() > 0) {
                        throw new AbortException(
                                " ---> Weaknesses entered in the weakness_is key were found during the scan. [Pipeline interrupted because the FAILED_ARGS arguments you entered were found...]");
                    }
                } else if (condition == "AND") {
                    if ((max_number_of_critical != null && critical > max_number_of_critical)
                            || (max_number_of_high != null && high > max_number_of_high)
                            || weaknessIsCount.size() > 0) {
                        throw new AbortException(
                                " ---> Not all conditions are met according to the given arguments. [Pipeline interrupted because the FAILED_ARGS arguments you entered were found...]");
                    }
                }

                Thread.sleep(3000);
                scanStatus = awaitScan(scanId, accessTokenSecret);
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

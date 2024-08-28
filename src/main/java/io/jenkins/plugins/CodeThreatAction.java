package io.jenkins.plugins;

import hudson.model.Action;
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

import hudson.model.Run;
import jenkins.model.RunAction2;

public class CodeThreatAction implements RunAction2  {

    private Number critical;
    private Number high;
    private Number medium;
    private Number low;
    private String durationTime;
    private String riskScore;
    private String resultsLink;
    private String report;
    private String projectName;
    private String fixedIssues;
    private JsonNode scaDeps;


    public CodeThreatAction(Number critical,Number high,Number medium,Number low, String durationTime,String riskScore, String resultsLink, String report, String projectName, String fixedIssues, JsonNode scaDeps) {
        this.critical = critical;
        this.high = high;
        this.medium = medium;
        this.low = low;
        this.durationTime = durationTime;
        this.riskScore = riskScore;
        this.resultsLink = resultsLink;
        this.report = report;
        this.projectName = projectName;
        this.fixedIssues = fixedIssues;
        this.scaDeps = scaDeps;
    }

    private transient Run run; 

    @Override
    public void onAttached(Run<?, ?> run) {
        this.run = run; 
    }

    @Override
    public void onLoad(Run<?, ?> run) {
        this.run = run; 
    }

    public Run getRun() { 
        return run;
    }

    public Number getCritical() {
        return critical;
    }

    public Number getHigh() {
        return high;
    }

    public Number getMedium() {
        return medium;
    }

    public Number getLow() {
        return low;
    }

    public String getDurationTime() {
        return durationTime;
    }

    public String getRiskScore() {
        return riskScore;
    }

    public String getResultsLink() {
        return resultsLink;
    }

    public String getReport() {
        return report;
    }

    public String getProjectName() {
        return projectName;
    }

    public String getFixedIssues() {
        return fixedIssues;
    }

    public JsonNode getScaDeps() {
        return scaDeps;
    }


    @Override
    public String getIconFileName() {
        return "/plugin/codethreat-scanner/img/cticon.png"; 
    }

    @Override
    public String getDisplayName() {
        return "CodeThreat Scan Result"; 
    }

    @Override
    public String getUrlName() {
        return "scanresult"; 
    }
}

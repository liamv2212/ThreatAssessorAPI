package com.example.threatassessorapi;

public class User {
    private String userName;
    private String password;
    private int orgID;

    public User(String userName, String password, int orgID) {
        this.userName = userName;
        this.password = password;
        this.orgID = orgID;
    }

    public User(String userName, int orgID) {
        this.userName = userName;
        this.password = "Hidden";
        this.orgID = orgID;
    }
    
    public String getUserName() {
        return userName;
    }
    public void setUserName(String userName) {
        this.userName = userName;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
    public String getOrgID() {
        return String.valueOf(orgID);
    }
    public void setOrgID(int orgID) {
        this.orgID = orgID;
    }

    public String toString() {
        return userName + "," + password + "," + orgID;
    }
}

package com.example.threatassessorapi;

public class Organization {
    String organizationName;
    int orgID;
    public Organization(String name, int id) {
        this.organizationName = name;
        this.orgID = id;
    }

    public String getName(){
        return this.organizationName;
    }
    public int getId(){
        return this.orgID;
    }
}

package com.example.threatassessorapi;

import java.util.Date;

public class Resource {
    private int id;
    private String type;
    private Date date;
    private int org_id;

    public Resource(int id, String type, Date date, int org_id){
        this.id = id;
        this.type = type;
        this.date = date;
        this.org_id = org_id;
    }

    public Resource(String type, Date date, int org_id){
        this.type = type;
        this.date = date;
        this.org_id = org_id;
    }

    public int getId() {return id;}
    public String getType() {return type; }
    public Date getDate() {return date; }
    public int getOrg_id() { return org_id; }
}

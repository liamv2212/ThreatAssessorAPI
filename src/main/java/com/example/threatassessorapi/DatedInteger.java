package com.example.threatassessorapi;

import java.sql.Date;

public class DatedInteger {
    Date partition_date;
    int count;
    public DatedInteger(Date partitionDate, int count) {
        this.partition_date = partitionDate;
        this.count = count;
    }
    public Date getPartition_date() {return partition_date;}
    public int getCount() {return count;}
}

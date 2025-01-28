package com.example.threatassessorapi;

import java.sql.Date;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Objects;

public class SQLHelpers {
//
//    public static void main(String[] args) throws Exception {
//        Long date = 1735232375000L;
//        getDateFilter(date, null);
//    }

    public static String getCriticalityFilter(String criticality){
        if (!Objects.isNull(criticality)) {
            if (criticality.equalsIgnoreCase("critical")) {
                criticality = "Critical";
            }
            if (criticality.equalsIgnoreCase("high")) {
                criticality = "High";
            }
            if (criticality.equalsIgnoreCase("medium")) {
                criticality = "Medium";
            }
            if (criticality.equalsIgnoreCase("low")) {
                criticality = "Low";
            }
            if (criticality.equalsIgnoreCase("info")) {
                criticality = "Info";
            }
            return " AND criticality = '"+criticality+"'";
        }
        else return "";
    }
    public static String getDateFilter(Long startDate, Long endDate) throws Exception {
        String rangeQuery = "";
        if (startDate != null && endDate != null) {
            LocalDate start, end;
            Instant startInstant = Instant.ofEpochMilli(startDate);
            ZoneId startZoneId = ZoneId.systemDefault();
            start = startInstant.atZone(startZoneId).toLocalDate();
            start = toMonday(start);
            Instant endInstant = Instant.ofEpochMilli(endDate);
            ZoneId endZoneId = ZoneId.systemDefault();
            end = endInstant.atZone(endZoneId).toLocalDate();
            end = toMonday(end);

            rangeQuery = " AND partition_date BETWEEN '" + start + "' AND '" + end + "'";
        }
        if (startDate != null && endDate == null) {
            LocalDate start;
            Instant instant = Instant.ofEpochMilli(startDate);
            ZoneId zoneId = ZoneId.systemDefault();
            start = instant.atZone(zoneId).toLocalDate();
            start = toMonday(start);
            LocalDate end = LocalDate.now();
            rangeQuery = " AND partition_date BETWEEN '" + start + "' AND '" + end + "'";
        }
        if (startDate == null && endDate != null) {
            throw new Exception("Start Date must be specified to use End Date");
        }
        return rangeQuery;
    }

    public static LocalDate getEndDate(Long endDate){
        Instant startInstant = Instant.ofEpochMilli(endDate);
        ZoneId startZoneId = ZoneId.systemDefault();
        return toMonday(startInstant.atZone(startZoneId).toLocalDate());

    }

    public static ArrayList<LocalDate> getStartDates(Long startDate, LocalDate end){
        ArrayList<LocalDate> startDates = new ArrayList<>();
        Instant startInstant = Instant.ofEpochMilli(startDate);
        ZoneId startZoneId = ZoneId.systemDefault();
        LocalDate start = toMonday(startInstant.atZone(startZoneId).toLocalDate());
        while (!start.equals(end)){
            startDates.add(start);
            start = start.plusWeeks(1);
        }
        return startDates;
    }

    public static ArrayList<LocalDate> getNewlyFoundStartDates(Long startDate, LocalDate end){
        ArrayList<LocalDate> startDates = new ArrayList<>();
        Instant startInstant = Instant.ofEpochMilli(startDate);
        ZoneId startZoneId = ZoneId.systemDefault();
        LocalDate start = toMonday(startInstant.atZone(startZoneId).toLocalDate());
        while (!start.equals(end)){
            startDates.add(start);
            start = start.plusWeeks(1);
        }
        startDates.add(end);
        return startDates;
    }

    public static ArrayList<LocalDate> getEndDates(ArrayList<LocalDate> startDates){
        ArrayList<LocalDate> endDates = new ArrayList<>();
        for (LocalDate startDate : startDates) {
            endDates.add(startDate.plusWeeks(1));
        }
        return endDates;
    }

    public static DatedInteger getDatedInteger(ResultSet rs, LocalDate endDate, String integerName) throws SQLException {
        if(rs.next()) {
            return new DatedInteger(
                    Date.valueOf(endDate),
                    rs.getInt(integerName)
            );
        }
        else{
           return new DatedInteger(
                    Date.valueOf(endDate),
                    0
            );
        }
    }

    public static VulnCount getVulnCount(ResultSet rs, LocalDate endDate) throws SQLException {
        return  new VulnCount(
                rs.getInt("resource_id"),
                rs.getString("resource_name"),
                rs.getInt("vulnCount"),
                Date.valueOf(endDate)
            );
    }

    public static String getHistoricalDateString(LocalDate startDate, LocalDate endDate){
        return " and partition_date in ('" + startDate + "', '"  + endDate + "')";
    }

    public static String getOSFilter(String OS) throws Exception {
        if (!Objects.isNull(OS)){
            return switch (OS.toLowerCase()) {
                case "windows", "linux", "mac" -> " AND operating_system =  '" + OS.toUpperCase() + "'";
                default -> throw new Exception("Unknown OS: " + OS.toUpperCase());
            };
        }
        else return "";
    }

    public static String getResourceTypeFilter(String resource_type) throws Exception {
        if(!Objects.isNull(resource_type)){
            return switch (resource_type.toLowerCase()){
            case "on-prem", "cloud" -> " AND resource_type = '" + resource_type.toUpperCase() + "'";
            default -> throw new Exception("Unknown resource_type: " + resource_type.toUpperCase());
            };
        }
        else return "";
    }


    public static LocalDate toMonday(LocalDate date) {
        switch (date.getDayOfWeek()) {
            case TUESDAY -> {
                return date.minusDays(1);
            }
            case WEDNESDAY -> {
                return date.minusDays(2);
            }
            case THURSDAY -> {
                return date.minusDays(3);
            }
            case FRIDAY -> {
                return date.minusDays(4);
            }
            case SATURDAY -> {
                return date.minusDays(5);
            }
            case SUNDAY -> {
                return date.minusDays(6);
            }
            default -> {
                return date;
            }
        }
    }
}

library('tidyverse')
library('stringr')
library('scales')
library('RColorBrewer')
#???library('sparkline')
library('formattable')
library('plotly')
library('leaflet')
library('htmltools')

#Sys.setenv('MAPBOX_TOKEN' = 'pk.eyJ1IjoiY2J1bHNhcmEiLCJhIjoiY2pmbXJ1emMxMGUxZDMzbXlkNnk0cHQzbSJ9.o3nHky3cH7VeadRQilaWVA')

source("Z:\\scripts\\dashboard\\discovery.R")
source("Z:\\scripts\\dashboard\\cmdb.R")

#------------DECLARE VARIABLES
setwd("Z:\\Dashboard\\2019\\")

inFile <- choose.files(caption = "Select Input File", multi = TRUE)
setwd("Z:\\powerbi\\")
csv_path <- 'C:\\csv\\vms\\'
csv_pattern <- 'metrics_Vulnerability_All_CriticalHigh.csv'

cols_as_factor <- c(
  'plugin_name',
  #'family',
  'severity',
  #'ip_address',
  #'protocol',
  #'port',
  #'exploit_',
  'exploit_ease'
)

cols_as_datetime <- c(
  'first_discovered',
  'last_observed',
  'patch_publication_date'
)
#------------READ FILES
csv_in <-
  list.files(path = inFile,
             full.name = TRUE)

df <- do.call(rbind, lapply(inFile, function(x)
  as.tibble(read.csv(x, sep=",", header=TRUE))))
latlon <- as.tibble(read.table('C:\\csv\\vms\\vms_sites.csv', sep=",", header=TRUE))

#------------TIDY DATA

#set blank values to NA
df[df==''] <- NA

#replace periods in column headers with underscore
names(df) <- gsub('\\.', '_', names(df)) 
names(df) <- gsub('\\?', '_', names(df)) 
#column headers to lower case
names(df) <- tolower(names(df))

#Other unordered factors
df[cols_as_factor] <-
  lapply(df[cols_as_factor], function(x)
    parse_factor(
      x,
      levels = NULL,
      ordered = TRUE,
      include_na = TRUE
    ))

#columns as datetime
df[cols_as_datetime] <-
  lapply(df[cols_as_datetime], function(x)
    parse_datetime(x, "%b %d, %Y %H:%M:%S %Z"))

#df$exploitable
#true if the exploit_ease field = "Exploits are available" or "No exploit is required"
df <- mutate(df, exploitable = (grepl("Exploits are available", exploit_ease, fixed=TRUE) | grepl("No exploit is required", exploit_ease, fixed=TRUE)))

#df$config_issue
#true if the exploit_ease field = "N/A"
df <- mutate(df, config_issue = is.na(exploit_ease))

#-------------------------Create Summaries

#Summarize by Severity
df_severity <- df %>% group_by(repository, severity) %>% summarize(n_vulnerabilities= n())
#df_severity <- df_severity %>% expand(repository,severity) %>% left_join(df_severity) %>% mutate_all(funs(replace(., is.na(.), 0)))

#group by site (repository) and severity
df_exec <-
  df %>% group_by(repository, exploitable) %>% dplyr::summarize(n_vulnerabilities = n())


df_merge <- merge(df_exec, df_summary, by = 'repository', all.x = TRUE)

#de-dupe and join
#df_dedupe and its children are useful because they yield unique assets and exploitable assets
#df_join_exp yields exploitable vulns and exploitable assets by location
df_dedupe <- df[!duplicated(df$ip_address), ]
df_dedupe_summary <-
  df_dedupe %>% group_by(repository, exploitable) %>% dplyr::summarize(unique_assets = n())
df_dedupe_summary <-
  merge(df_dedupe_summary,
        df_summary,
        by = 'repository',
        all.x = TRUE)
df_dedupe_summary <-
  df_dedupe_summary %>% mutate(ptotal = unique_assets / total)
df_join <- inner_join(df_dedupe_summary, df_merge)
df_join <-
  df_join %>% expand(repository, exploitable) %>% left_join(df_join) %>% mutate_all(funs(replace(., is.na(.), 0)))
df_join$exploitable <- as.logical(df_join$exploitable)
df_join_exp <-
  df_join[(df_join$exploitable == 'TRUE'), ] %>% mutate(exploitable_assets = unique_assets)

df_join_exp <- df_join_exp %>% mutate(measure_date = format(Sys.Date(), format = "%m/%d/%y"))
df_join_nexp <-
  df_join[(df_join$exploitable == 'FALSE'), ] %>% mutate(nexploitable_assets = unique_assets)

#-------------------------Power BI
df_powerbi1 <- df_dedupe %>% group_by(first_discovered, exploitable) %>% summarize(unique_assets=n()) %>% filter(exploitable == "TRUE")
df_powerbi1$sAssets <- cumsum(df_powerbi1$unique_assets)
df_powerbi2 <- df %>% group_by(first_discovered, exploitable) %>% dplyr::summarize(n_vulnerabilities = n()) %>% filter(exploitable == TRUE)
df_powerbi2$sVulns <- cumsum(df_powerbi2$n_vulnerabilities)
df_powerbi <- merge(df_powerbi1, df_powerbi2, by = 'first_discovered', all.x = TRUE)
df_powerbi <- unique(df_powerbi)
#-------------------------Map
df_exploitable <-
  df[df$exploitable == 'TRUE', ] %>% group_by(repository) %>% summarize(n_exploitable = n())
df_nonexploitable <-
  df[df$exploitable == 'FALSE', ] %>% group_by(repository) %>% summarize(n_nexploitable = n())
df_map <-
  merge(df_exploitable,
        df_nonexploitable,
        by = 'repository',
        all.x = TRUE)
df_map <-
  merge(df_map, df_join[, c('repository', 'unique_assets')], by = 'repository', all.x =
          'TRUE')
df_map <- df_map[!duplicated(df_map$repository), ]
df_map <-
  merge(df_map, latlon[, c('repository', 'site_lons', 'site_lats')], by =
          "repository", all.x = TRUE)
df_map <-
  merge(df_map, df_join_exp[, c('repository', 'exploitable_assets')], by =
          'repository', all.x = TRUE)
df_map <-
  merge(df_map, df_join_nexp[, c('repository', 'nexploitable_assets')], by =
          'repository', all.x = TRUE)

#-------------------------Power BI CSVs

#Read the existing CSV
existing <- as.tibble(read.table('vmsVulnsAssets.csv', sep=",", header=TRUE, quote='"'))
existing$first_discovered <- parse_date(existing$first_discovered, format="%Y-%m-%d")
#RBind it with new rows
all <- unique(rbind(existing, df_powerbi))
#write the csv
write.csv(all, file="vmsVulnsAssets.csv", row.names=FALSE)

#-------------------------Remediation
df_remediation <- df %>% group_by(plugin_name) %>% filter(exploit_ease == 'No exploit is required' | exploit_ease == 'Exploits are available' | is.na(exploit_ease))
df_remediation <- subset(df_remediation, select=c('plugin', 'plugin_name','synopsis', 'severity', 'cve', 'ip_address', 'dns_name', 'netbios_name'))
df_remediation <- df_remediation %>% mutate(group = 
                                                    case_when(grepl("DT",netbios_name) | grepl("LT",netbios_name) | grepl("CTX",netbios_name)~ "DEA",
                                                              grepl("SA",netbios_name) | grepl("sa",dns_name) | grepl("ST",netbios_name) | grepl("st",dns_name) | grepl("SI",netbios_name) | grepl("si",dns_name) ~ "WCP"))
#take the asset name portion of the dns name or netbios name, whichever is not NA
df_remediation <- df_remediation %>% mutate(name = ifelse(is.na(dns_name), ifelse(is.na(netbios_name), NA, gsub(".*\\\\","",netbios_name)), gsub("\\..*", "", dns_name)))

#convert to uppercase for comparision against cmdb
df_remediation$name <- toupper(df_remediation$name)

#merge with cmdb based on asset name, pull in supported_by field
df_remediation <- merge(df_remediation, na.omit(df_cmdb[, c("name", "supported_by")]), by = "name", all.x = TRUE)

#-------------------------Generate Remediation CSVs - moved to vmsRemediation.R
#for (p in unique(df_remediation$plugin)) {
#  df_rm <- df_remediation %>% filter(plugin == p)
#  path <-'Z:\\Dashboard\\nessus\\remediation\\'
#  filename <- paste(df_rm[1,]$plugin, "_", df_rm[1,]$severity, ".csv", sep = "")
#  write.csv(df_rm, file = paste(path, filename, sep = ""))
#}

#-------------------------Create plots

#Stacked bar, exploitable vs non by Repository
repos <- unique(df_join$repository)
non_exp <- df_join[df_join$exploitable=='FALSE',]$n_vulnerabilities
exp <- df_join[df_join$exploitable=='TRUE',]$n_vulnerabilities
sum_vulns <- exp + non_exp
df_vuln <- data.frame (repos, exp, non_exp)
p_VulnsbySite <-plot_ly(df_vuln, 
                  x=~repos, y=~exp, 
                  type = 'bar', 
                  text = ~exp, textposition = 'auto', 
                  name = 'Exploitable') %>% 
              add_trace(y = ~non_exp, text = ~non_exp, 
                  name = 'Non-Exploitable') %>% 
              layout (title = "Vulnerabilities By Site", 
                  xaxis = list(title = 'Site'), 
                  yaxis = list(title = '# of Vulnerabilities'), 
                  barmode = 'stack')

#Stacked bar, Critical vs High by Repository
#re-use repos
#repos <- unique(df_join$repository)
crit <- df_severity[df_severity$severity=='Critical',]$n_vulnerabilities
high <- df_severity[df_severity$severity=='High',]$n_vulnerabilities
#df_sev <- data.frame(repos, crit, high)
p_SevbySite <-plot_ly(df_severity, 
                        x=~repos, y=~high, 
                        type = 'bar', 
                        text = ~high, textposition = 'auto', 
                        name = 'High Risk') %>% 
              add_trace(y = ~crit, text = ~crit, 
                        name = 'Critical') %>% 
              layout (title = "Severity By Site", 
                        xaxis = list(title = 'Site'), 
                        yaxis = list(title = '# of Vulnerabilities'), 
                        barmode = 'stack')


#Pie chart, assets affected by Critical and High vulnerabilities
#re-use repos from p_VulnsbySite
#repos <- unique(df_join$repository)
assets_n <- df_join[df_join$exploitable=='FALSE',]$unique_assets
assets_y <- df_join[df_join$exploitable=='TRUE',]$unique_assets
#exp_assets <- assets_n + assets_y
exp_assets <- assets_y
sum_assets <- sum(exp_assets, assets_n)
asset_totals <- df_join[df_join$exploitable=='TRUE',]$total
df_asset <- data.frame(repos,exp_assets,asset_totals)
df_asset <- df_asset %>% mutate(p = exp_assets/asset_totals)
piedata <- df_asset[,c('repos','exp_assets')]
pietitle <-paste("% Breakdown of", sum_assets, "Vulnerable Assets by Location", sep = " ")
p_VulnPercent <- plot_ly(piedata, 
                          labels = ~repos, 
                          values = ~exp_assets, 
                          type = 'pie', 
                          textposition='inside', 
                          textinfo='label+percent',
                          hoverinfo='text',
                          text=~paste(exp_assets, "assets")) %>%
  
                layout(title = pietitle)

#Map of sites

#df_location <- data.frame(repos, exp_assets, exp, lats, lons)
m_label <- paste("Site:", df_map$repository, "<br/>Vulnerable Assets:", df_map$exploitable_assets, 
                 "<br/>Exploitable Vulns: ", df_map$n_exploitable, sep = " ") %>% lapply(htmltools::HTML) 
m <- leaflet (data=df_map)
m <- m %>% addTiles(group = "OSM (default)") %>%
  #addProviderTiles(providers$Stamen.Toner, group = "Toner") %>% addCircleMarkers(~lons, ~lats, label = m_label, color = 'red', radius = ~exp_assets/10)
  addProviderTiles(providers$CartoDB.Positron) %>% 
  addCircleMarkers(~site_lons, ~site_lats, label = m_label, color = 'red', radius = ~exp_assets/5)
  
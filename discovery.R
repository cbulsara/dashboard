library('tidyverse')
library('stringr')
library('scales')
library('RColorBrewer')
#library('sparkline')
library('formattable')

source("C:\\dashboard_alpha-master\\cmdb.R")

#------------DECLARE VARIABLES
csv_path <- 'C:\\csv\\vms\\'
csv_pattern <- 'metrics_discovery_all.csv'

cols_as_factor <- c(
  'os_cpe',
  'repository'
)

#------------READ FILES
inFile <- choose.files(caption = "Select Discovery File", multi = TRUE)

csv_in <-
  list.files(path = inFile,
             full.name = TRUE)

#csv_in <-
#  list.files(path = csv_path,
#             pattern = csv_pattern,
#             full.name = TRUE)

df_disco <- do.call(rbind, lapply(inFile, function(x)
  as.tibble(read.csv(x, sep=",", header=TRUE))))

#------------TIDY DATA

#set blank values to NA
df_disco[df_disco==''] <- NA

#replace periods in column headers with underscore
names(df_disco) <- gsub('\\.', '_', names(df_disco)) 
names(df_disco) <- gsub('\\?', '_', names(df_disco))
names(df_disco) <- gsub(' ', '_', names(df_disco))
#column headers to lower case
names(df_disco) <- tolower(names(df_disco))

#Other unordered factors
df_disco[cols_as_factor] <-
  lapply(df_disco[cols_as_factor], function(x)
    parse_factor(
      x,
      levels = NULL,
      ordered = TRUE,
      include_na = TRUE
    ))

df_disco <- df_disco %>% mutate(name = ifelse(is.na(dns_name), ifelse(is.na(netbios_name), NA, gsub(".*\\\\","",netbios_name)), gsub("\\..*", "", dns_name)))

#convert to uppercase for comparision against cmdb
df_disco$name <- toupper(df_disco$name)

#merge with cmdb based on asset name, pull in supported_by field
df_disco <- merge(df_disco, na.omit(df_cmdb[, c("name", "supported_by")]), by = "name", all.x = TRUE)
#df_disco <- merge(df_disco, na.omit(df_cmdb[, c("name", "ip_address", "supported_by")]), all.x = TRUE)
df_namena <- df_disco[is.na(df_disco$name),]
df_supportedna <- df_disco[is.na(df_disco$supported_by),]

df_summary <- df_disco %>% group_by(repository) %>% dplyr::summarize(total = n())
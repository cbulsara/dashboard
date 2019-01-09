library('tidyverse')
library('stringr')
library('scales')
library('RColorBrewer')
#library('sparkline')
library('formattable')

#------------DECLARE VARIABLES

csv_path <- 'C:\\csv\\cmdb\\'
csv_pattern <- '*.csv'

cols_as_factor <- c(
  'owned_by',
  'managed_by',
  'supported_by',
  'support_group',
  'assignment_group'
)

#------------READ FILES
inFile <- choose.files(caption = "Select CMDB File", multi = TRUE)

csv_in <-
  list.files(path = inFile,
             full.name = TRUE)

#csv_in <-
#  list.files(path = csv_path,
#             pattern = csv_pattern,
#             full.name = TRUE)

df <- do.call(rbind, lapply(inFile, function(x)
  as.tibble(read.csv(x, sep=",", header=TRUE))))

#------------TIDY DATA

#set blank values to NA
df[df==''] <- NA

#replace periods in column headers with underscore
names(df) <- gsub('\\.', '_', names(df)) 
names(df) <- gsub('\\?', '_', names(df)) 
#column headers to lower case
names(df) <- tolower(names(df))
df_cmdb <- df
df_cmdb$name <- toupper(df_cmdb$name)
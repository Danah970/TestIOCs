rule RId_15677_Regression_Yara_Rule {
  strings:
    $string1 = "Malware"
    $string2 = "Content"
  condition:
    ($string1 and $string2)
}
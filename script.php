<?php
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="sample.csv"');
 
    $fp = fopen('php://output', 'wb');
 
    $years = array(2016, 2017, 2018, 2019); // Years to extract the info from
    foreach($years as $year) {
        $url = 'https://portal.msrc.microsoft.com/api/security-guidance/en-us/acknowledgments/year/' . $year; // API endpoint for retrieval of data
        $pageData = json_decode(file_get_contents($url)); // Fetch the data and convert into an Object
 
        fputcsv($fp, array( // Insert labels to CSV
            'Vulnerability name',
            'CVE ID',
            'Acknowledgement',
            'Date published',
            'Description (FL)',
            'Max Base CVSS score applied',
            'Exploited'
        ));
 
        foreach($pageData->details as $value) {
            $row = array();
            $row[] = $value->cveTitle; // 1
            $row[] = $value->cveNumber; // 2
            $akl = ''; // 3
            foreach($value->acknowledgments as $akValue) { // Adds all acknowledgments
                $akl .= $akValue . ', ';
            }
            $akl = substr($akl, 0, -2);
            $row[] = $akl;
            $row[] = $value->publishedDate; // 4
 
            if($value->cveNumber) {
                $cveURL = 'https://portal.msrc.microsoft.com/api/security-guidance/en-us/CVE/' . $value->cveNumber; // API endpoint for retrieval of data
                $pageData = json_decode(file_get_contents($cveURL)); // Fetch the data and convert into an Object 
 
                $first_dot_pos = strpos($pageData->description, '.'); // Check if a dot exists and where in order to identify the first line // 5
                $description = $first_dot_pos ? (substr($pageData->description, 0, $first_dot_pos)) : ($pageData->description);
                $row[] = $description;
                $max_base = 0; // 6
                foreach($pageData->affectedProducts as $ap) { // Checking the highest number
                    if($ap->baseScore > $max_base) {
                        $max_base = $ap->baseScore;
                    }
                }
                $row[] = $max_base;
                $row[] = $pageData->exploited ? ($pageData->exploited) : (''); // 7
            } else {
                $row[] = 'NO CVE'; // 5
                $row[] = 'NO CVE'; // 6
                $row[] = 'NO CVE'; // 7
            }
 
            fputcsv($fp, $row); // Insert a new row to the CSV
        }
    }
 
    fclose($fp);
?>

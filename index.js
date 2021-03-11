// dependencies
const AWS = require('aws-sdk');
const CloudmersiveVirusApiClient = require('cloudmersive-virus-api-client');
// const sharp = require('sharp');

// get reference to S3 client
const s3 = new AWS.S3();

function scanFileAsPromise(instance, inputFile) {
    return new Promise((resolve, reject) => {
        instance.scanFile(inputFile, (error, data, response) => {
            if (error) {
                // an error occurred
                reject(error);
            } else {
                // successful response
                resolve(data);
            }
        });
    });
}

function changeTagPromise(param) {
    return new Promise((resolve, reject) => {
        s3.putObjectTagging(param, (err, data) => {
            if (err) {
                // an error occurred
                reject(err)
            } else {
                // successful response
                resolve(data);
            }
        });
    });
}

exports.handler = async(event, context, callback) => {

    // Read options from the event parameter.
    const srcBucket = event.Records[0].s3.bucket.name;
    // Object key may have spaces or unicode non-ASCII characters.
    const srcKey = decodeURIComponent(event.Records[0].s3.object.key.replace(/\+/g, " "));


    // Download the file from the S3 source bucket.

    try {
        const params = {
            Bucket: srcBucket,
            Key: srcKey
        };
        let originFile = await s3.getObject(params).promise();

        // Scan virus through API
        var defaultClient = CloudmersiveVirusApiClient.ApiClient.instance;

        // Configure API key authorization: Apikey
        var Apikey = defaultClient.authentications['Apikey'];
        Apikey.apiKey = 'YOUR-API-KEY';


        var apiInstance = new CloudmersiveVirusApiClient.ScanApi();

        var inputFile = originFile.Body; // File | Input file to perform the operation on.

        try {
            const res = await scanFileAsPromise(apiInstance, inputFile);
            console.log('Promise called - ', res);
            if (res.FoundViruses) {
                // condition when found virus from file

                var newParams = {
                    Bucket: srcBucket,
                    Key: srcKey,
                    Tagging: {
                        TagSet: [{
                            Key: "VirusScanResult",
                            Value: "Infected"
                        }]
                    }
                };

                try {
                    await changeTagPromise(newParams)
                } catch (e) {
                    console.log("error occered while changing tag", e)
                }
            } else {
                // condition when no virus on file

                var newParams = {
                    Bucket: srcBucket,
                    Key: srcKey,
                    Tagging: {
                        TagSet: [{
                            Key: "VirusScanResult",
                            Value: "Clean"
                        }]
                    }
                };

                try {
                    await changeTagPromise(newParams)
                } catch (e) {
                    console.log("error occered while changing tag", e)
                }
            }

        } catch (e) {
            console.log("==============error occuered", e);
        }

    } catch (error) {
        // console.log("Bucket", srcBucket, "key===>", srcKey, "error while downloading the origin file=============", error);
        return;
    }
};
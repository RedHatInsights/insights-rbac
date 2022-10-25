## OCM Performance Local Test Results

To run the tests locally, use:

```
python rbac/manage.py ocm_performance [test|setup|teardown|full_sync_only]
```

You can change the number of tenants and other db entries created in the test_performance_util file. Also, a synchronous version of the tests is provided for local dev.

## Results

### Concurrent Test Runs
```
Starting test for Full Sync...
Total request time: 374.0565104750001 seconds
Average time: 0.017812214784523814 seconds
Number of requests: 21000
---------------------------

Starting test for Tenant Groups...
Total request time: 22.337278276000006 seconds
Average time: 0.022337278276000006 seconds
Number of requests: 1000
---------------------------

Starting test for Tenant Roles...
Total request time: 17.58727593699996 seconds
Average time: 0.01758727593699996 seconds
Number of requests: 1000
---------------------------

Starting test for Group Roles...
Total request time: 254.58830115199999 seconds
Average time: 0.254588301152 seconds
Number of requests: 1000
---------------------------

Starting test for Principals Groups...
Total request time: 191.95753976599985 seconds
Average time: 0.019195753976599984 seconds
Number of requests: 10000
---------------------------
```

```
Starting test for Full Sync...
Total request time: 309.92920772900015 seconds
Average time: 0.01475853370138096 seconds
Number of requests: 21000
---------------------------

Starting test for Tenant Groups...
Total request time: 20.383814118000373 seconds
Average time: 0.020383814118000373 seconds
Number of requests: 1000
---------------------------

Starting test for Tenant Roles...
Total request time: 18.35850164399926 seconds
Average time: 0.018358501643999263 seconds
Number of requests: 1000
---------------------------

Starting test for Group Roles...
Total request time: 227.5744315639995 seconds
Average time: 0.2275744315639995 seconds
Number of requests: 1000
---------------------------

Starting test for Principals Groups...
Total request time: 174.27560497500053 seconds
Average time: 0.017427560497500053 seconds
Number of requests: 10000
---------------------------
```

```
Starting test for Full Sync...
Total request time: 284.5034908010002 seconds
Average time: 0.013547785276238107 seconds
Number of requests: 21000
---------------------------

Starting test for Tenant Groups...
Total request time: 18.46951627100043 seconds
Average time: 0.01846951627100043 seconds
Number of requests: 1000
---------------------------

Starting test for Tenant Roles...
Total request time: 17.101372801999787 seconds
Average time: 0.017101372801999786 seconds
Number of requests: 1000
---------------------------

Starting test for Group Roles...
Total request time: 213.59555220899983 seconds
Average time: 0.21359555220899984 seconds
Number of requests: 1000
---------------------------

Starting test for Principals Groups...
Total request time: 158.98659055700045 seconds
Average time: 0.015898659055700044 seconds
Number of requests: 10000
---------------------------
```

### Linear Test Runs
```
Starting test for Full Sync...
Total request time: 239.74237182700108 seconds
Average time: 0.011416303420333385 seconds
Number of requests: 21000
---------------------------

Starting test for Tenant Groups...
Total request time: 19.001369553998302 seconds
Average time: 0.019001369553998303 seconds
Number of requests: 1000
---------------------------

Starting test for Tenant Roles...
Total request time: 16.493675307001467 seconds
Average time: 0.01649367530700147 seconds
Number of requests: 1000
---------------------------

Starting test for Group Roles...
Total request time: 174.2605710029984 seconds
Average time: 0.01742605710029984 seconds
Number of requests: 10000
---------------------------

Starting test for Principals Groups...
Total request time: 160.510998826001 seconds
Average time: 0.0160510998826001 seconds
Number of requests: 10000
---------------------------

```
```
Starting test for Full Sync...
Total request time: 238.58747291799955 seconds
Average time: 0.011361308234190454 seconds
Number of requests: 21000
---------------------------

Starting test for Tenant Groups...
Total request time: 18.308321327998783 seconds
Average time: 0.018308321327998783 seconds
Number of requests: 1000
---------------------------

Starting test for Tenant Roles...
Total request time: 15.739753075000408 seconds
Average time: 0.015739753075000407 seconds
Number of requests: 1000
---------------------------

Starting test for Group Roles...
Total request time: 180.76433535099932 seconds
Average time: 0.018076433535099933 seconds
Number of requests: 10000
---------------------------

Starting test for Principals Groups...
Total request time: 165.74606060400038 seconds
Average time: 0.016574606060400038 seconds
Number of requests: 10000
---------------------------
```

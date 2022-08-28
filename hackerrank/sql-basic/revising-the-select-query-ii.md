## Question

- Link: `https://www.hackerrank.com/challenges/revising-the-select-query-2/problem?isFullScreen=true`

![image](https://user-images.githubusercontent.com/68887544/187087839-559958c6-f09f-43d3-b517-b2b22ab281f2.png)

## Database

```
6 Rotterdam NLD Zuid-Holland 593321
3878 Scottsdale USA Arizona 202705
3965 Corona USA California 124966
3973 Concord USA California 121780
3977 Cedar Rapids USA Iowa 120758
3982 Coral Springs USA Florida 117549
4054 Fairfield USA California 92256
4058 Boulder USA Colorado 91238
4061 Fall River USA Massachusetts 90555
```

## Solution

```
select name from city where population > 120000 and countrycode = "usa";
```

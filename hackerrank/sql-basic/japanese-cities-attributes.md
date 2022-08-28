## Question

![image](https://user-images.githubusercontent.com/68887544/187088189-0d116a2b-31b5-4196-8f6e-ba573b4bfe92.png)

## Database

```
6 Rotterdam NLD Zuid-Holland 593321
19 Zaanstad NLD Noord-Holland 135621
214 Porto Alegre BRA Rio Grande do Sul 1314032
397 Lauro de Freitas BRA Bahia 109236
547 Dobric BGR Varna 100399
552 Bujumbura BDI Bujumbura 300000
554 Santiago de Chile CHL Santiago 4703954
626 al-Minya EGY al-Minya 201360
646 Santa Ana SLV Santa Ana 139389
762 Bahir Dar ETH Amhara 96140
796 Baguio PHL CAR 252386
896 Malungon PHL Southern Mindanao 93232
904 Banjul GMB Banjul 42326
924 Villa Nueva GTM Guatemala 101295
990 Waru IDN East Java 124300
1155 Latur IND Maharashtra 197408
1222 Tenali IND Andhra Pradesh 143726
1235 Tirunelveli IND Tamil Nadu 135825
1256 Alandur IND Tamil Nadu 125244
1279 Neyveli IND Tamil Nadu 118080
1293 Pallavaram IND Tamil Nadu 111866
1350 Dehri IND Bihar 94526
1383 Tabriz IRN East Azerbaidzan 1191043
1385 Karaj IRN Teheran 940968
1508 Bolzano ITA Trentino-Alto Adige 97232
1520 Cesena ITA Emilia-Romagna 89852
1613 Neyagawa JPN Osaka 257315
1630 Ageo JPN Saitama 209442
1661 Sayama JPN Saitama 162472
1681 Omuta JPN Fukuoka 142889
1739 Tokuyama JPN Yamaguchi 107078
1793 Novi Sad YUG Vojvodina 179626
1857 Kelowna CAN British Colombia 89442
1895 Harbin CHN Heilongjiang 4289800
1900 Changchun CHN Jilin 2812000
1913 Lanzhou CHN Gansu 1565800
1947 Changzhou CHN Jiangsu 530000
2070 Dezhou CHN Shandong 195485
2081 Heze CHN Shandong 189293
2111 Chenzhou CHN Hunan 169400
2153 Xianning CHN Hubei 136811
2192 Lhasa CHN Tibet 120000
2193 Lianyuan CHN Hunan 118858
2227 Xingcheng CHN Liaoning 102384
2273 Villavicencio COL Meta 273140
2384 Tong-yong KOR Kyongsangnam 131717
2386 Yongju KOR Kyongsangbuk 131097
2387 Chinhae KOR Kyongsangnam 125997
2388 Sangju KOR Kyongsangbuk 124116
2406 Herakleion GRC Crete 116178
2440 Monrovia LBR Montserrado 850000
2462 Lilongwe MWI Lilongwe 435964
2505 Taza MAR Taza-Al Hoceima-Taou 92700
2555 Xalapa MEX Veracruz 390058
2602 Ocosingo MEX Chiapas 171495
2609 Nogales MEX Sonora 159103
2670 San Pedro Cholula MEX Puebla 99734
2689 Palikir FSM Pohnpei 8600
2706 Tete MOZ Tete 101984
2716 Sittwe (Akyab) MMR Rakhine 137600
2922 Carolina PRI Carolina 186076
2967 Grudziadz POL Kujawsko-Pomorskie 102434
2972 Malabo GNQ Bioko 40000
3073 Essen DEU Nordrhein-Westfalen 599515
3169 Apia WSM Upolu 35900
3198 Dakar SEN Cap-Vert 785071
3253 Hama SYR Hama 343361
3288 Luchou TWN Taipei 160516
3309 Tanga TZA Tanga 137400
3353 Sousse TUN Sousse 145900
3377 Kahramanmaras TUR Kahramanmaras 245772
3430 Odesa UKR Odesa 1011000
3581 St Petersburg RUS Pietari 4694000
3770 Hanoi VNM Hanoi 1410000
3815 El Paso USA Texas 563662
3878 Scottsdale USA Arizona 202705
3965 Corona USA California 124966
3973 Concord USA California 121780
3977 Cedar Rapids USA Iowa 120758
3982 Coral Springs USA Florida 117549
4054 Fairfield USA California 92256
4058 Boulder USA Colorado 91238
4061 Fall River USA Massachusetts 90555
```
## Solution:

```
select * from city where countrycode = "jpn";
```

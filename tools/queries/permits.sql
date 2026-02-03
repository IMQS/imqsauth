WITH permits as (SELECT
                   t.userid,
                   array_agg(
                     ((get_byte(p, i)     ::bigint << 24) |
                       (get_byte(p, i + 1) ::bigint << 16) |
                       (get_byte(p, i + 2) ::bigint << 8)  |
                       get_byte(p, i + 3) ::bigint)
    ORDER BY i
  ) AS groups
                 FROM authuserpwd t
                        CROSS JOIN LATERAL (
                     SELECT decode(t.permit, 'base64') AS p
                       ) d
                        CROSS JOIN LATERAL generate_series(0, length(p) - 1, 4) AS i
WHERE length(p) % 4 = 0
GROUP BY t.userid
  )
SELECT aus.userid, username,
  permits.groups
FROM public.authuserstore aus
       join authuserpwd a on aus.userid = a.userid
       join permits on aus.userid = permits.userid
       join authgroup on authgroup."name" ilike 'enabled'
where (email ilike '%yoursearchpathhere%' or email ilike '%yoursearchpathhere')
  and (archived is not true)
and (authgroup.id = ANY(permits.groups))
order by aus.userid
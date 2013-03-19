function sprofile_init(nsamples::Integer, delay::Integer)
    status = ccall(:jl_sprofile_init, Cint, (Uint64, Uint), nsamples, delay)
    if status == -1
        error("Could not allocate space for ", nsamples, " profiling samples")
    end
end

sprofile_start_timer() = ccall(:jl_sprofile_start_timer, Int32, ())

sprofile_stop_timer() = ccall(:jl_sprofile_stop_timer, Void, ())

sprofile_get_data_pointer() = convert(Ptr{Uint}, ccall(:jl_sprofile_get_data, Ptr{Uint8}, ()))

sprofile_len_data() = convert(Int, ccall(:jl_sprofile_len_data, Uint, ()))

sprofile_maxlen_data() = convert(Int, ccall(:jl_sprofile_maxlen_data, Uint, ()))


sprofile_clear() = ccall(:jl_sprofile_clear_data, Void, ())

function sprofile_lookup(ip::Uint, doCframes::Bool)
    info = ccall(:jl_lookup_code_address, Any, (Ptr{Void}, Bool), ip, doCframes)
    if length(info) == 3
        return string(info[1]), string(info[2]), info[3]
    else
        return info
    end
end

sprofile_error_codes = (Int=>ASCIIString)[
    -1=>"Cannot specify signal action for profiling",
    -2=>"Cannot create the timer for profiling",
    -3=>"Cannot start the timer for profiling"]

function sprofile_get()
    len = sprofile_len_data()
    maxlen = sprofile_maxlen_data()
    if (len == maxlen)
        warn("the profile data buffer is full; profiling probably terminated\nbefore your program finished. To profile for longer runs, call sprofile_init()\nwith a larger buffer and/or larger delay.")
    end
    pointer_to_array(sprofile_get_data_pointer(), (len,))
end


# Number of backtrace "steps" that are triggered by taking the backtrace, e.g.,
# inside profile_bt. May be platform-specific?
const btskip = 2

## A simple linecount parser
function sprofile_parse_flat(doCframes::Bool)
    data = sprofile_get()
    linecount = (Uint=>Int)[]
    toskip = btskip
    for ip in data
        if toskip > 0
            toskip -= 1
            continue
        end
        if ip == 0
            toskip = btskip
            continue
        end
        linecount[ip] = get(linecount, ip, 0)+1
    end
    # Extract dict as arrays
    buf = Array(Uint, 0)
    n = Array(Int, 0)
    for (k,v) in linecount
        push!(buf, k)
        push!(n, v)
    end
    # Convert instruction pointers to names & line numbers
    bt = Array(Any, length(buf))
    for i = 1:length(buf)
        bt[i] = sprofile_lookup(buf[i], doCframes)
    end
    # Keep only the interpretable ones
    # The ones with no line number might appear multiple times in a single
    # capture, giving the wrong impression about the total number of captures.
    # Delete them too.
    keep = !Bool[isempty(x) || x[3] == 0 for x in bt]
    n = n[keep]
    bt = bt[keep]
    bt, n
end

function sprofile_flat(io::IO, doCframes::Bool, mergelines::Bool, cols::Int)
    bt, n = sprofile_parse_flat(doCframes)
    p = sprof_sortorder(bt)
    n = n[p]
    bt = bt[p]
    if mergelines
        j = 1
        for i = 2:length(bt)
            if bt[i] == bt[j]
                n[j] += n[i]
                n[i] = 0
            else
                j = i
            end
        end
        keep = n .> 0
        n = n[keep]
        bt = bt[keep]
    end
    wcounts = max(6, ndigits(max(n)))
    maxline = 0
    maxfile = 0
    maxfun = 0
    for thisbt in bt
        maxline = max(maxline, thisbt[3])
        maxfile = max(maxfile, length(thisbt[2]))
        maxfun = max(maxfun, length(thisbt[1]))
    end
    wline = max(12, ndigits(maxline))
    ntext = cols - wcounts - wline - 3
    if maxfile+maxfun <= ntext
        wfile = maxfile
        wfun = maxfun
    else
        wfile = ifloor(2*ntext/5)
        wfun = ifloor(3*ntext/5)
    end
    println(io, lpad("Count", wcounts, " "), " ", rpad("File", wfile, " "), " ", rpad("Function", wfun, " "), " ", lpad("Line/offset", wline, " "))
    for i = 1:length(n)
        thisbt = bt[i]
        println(io, lpad(string(n[i]), wcounts, " "), " ", rpad(truncto(thisbt[2], wfile), wfile, " "), " ", rpad(truncto(thisbt[1], wfun), wfun, " "), " ", lpad(string(thisbt[3]), wline, " "))
    end
end
sprofile_flat(io::IO) = sprofile_flat(io, false, false, tty_cols())
sprofile_flat() = sprofile_flat(OUTPUT_STREAM)
sprofile_flat(doCframes::Bool, mergelines::Bool) = sprofile_flat(OUTPUT_STREAM, doCframes,  mergelines, tty_cols())

## A tree representation
function sprof_tree()
    data = sprofile_get()
    iz = find(data .== 0)  # find the breaks between captures
    treecount = (Vector{Uint}=>Int)[]
    istart = 1+btskip
    for iend in iz
        tmp = data[iend-1:-1:istart]
        treecount[tmp] = get(treecount, tmp, 0)+1
        istart = iend+1+btskip
    end
    bt = Array(Vector{Uint}, 0)
    counts = Array(Int, 0)
    for (k,v) in treecount
        push!(bt, k)
        push!(counts, v)
    end
    bt, counts
end

function sprof_treematch(bt::Vector{Vector{Uint}}, counts::Vector{Int}, pattern::Vector{Uint})
    l = length(pattern)
    n = length(counts)
    matched = falses(n)
    for i = 1:n
        k = bt[i]
        if length(k) >= l && k[1:l] == pattern
            matched[i] = true
        end
    end
    matched
end

sprof_tree_format_linewidth(x) = isempty(x) ? 0 : ndigits(x[3])+6

function sprof_tree_format(infoa::Vector{Any}, counts::Vector{Int}, level::Int, cols::Integer)
    nindent = min(ifloor(cols/2), level)
    ndigcounts = ndigits(max(counts))
    ndigline = max([sprof_tree_format_linewidth(x) for x in infoa])
    ntext = cols-nindent-ndigcounts-ndigline-5
    widthfile = ifloor(0.4ntext)
    widthfunc = ifloor(0.6ntext)
    strs = Array(ASCIIString, length(infoa))
    showextra = false
    if level > nindent
        nextra = level-nindent
        nindent -= ndigits(nextra)+2
        showextra = true
    end
    for i = 1:length(infoa)
        info = infoa[i]
        if !isempty(info)
            base = " "^nindent
            if showextra
                base = string(base, "+", nextra, " ")
            end
            base = string(base,
                          rpad(string(counts[i]), ndigcounts, " "),
                          " ",
                          truncto(string(info[2]), widthfile),
                          "; ",
                          truncto(string(info[1]), widthfunc),
                          "; ")
            strs[i] = string(base, "line: ", info[3])
        else
            strs[i] = ""
        end
    end
    strs
end
sprof_tree_format(infoa::Vector{Any}, counts::Vector{Int}, level::Int) = sprof_tree_format(infoa, counts, level, tty_cols())

function sprofile_tree(io, bt::Vector{Vector{Uint}}, counts::Vector{Int}, level::Int, doCframes::Bool)
    umatched = falses(length(counts))
    len = Int[length(x) for x in bt]
    infoa = Array(Any, 0)
    keepa = Array(BitArray, 0)
    n = Array(Int, 0)
    while !all(umatched)
        ind = findfirst(!umatched)
        pattern = bt[ind][1:level+1]
        matched = sprof_treematch(bt, counts, pattern)
        push!(infoa, sprofile_lookup(pattern[end], doCframes))
        keep = matched & (len .> level+1)
        push!(keepa, keep)
        umatched |= matched
        push!(n, sum(counts[matched]))
    end
    p = sprof_sortorder(infoa)
    infoa = infoa[p]
    keepa = keepa[p]
    n = n[p]
    strs = sprof_tree_format(infoa, n, level)
    for i = 1:length(infoa)
        if !isempty(strs[i])
            println(io, strs[i])
        end
        keep = keepa[i]
        if any(keep)
            sprofile_tree(io, bt[keep], counts[keep], level+1, doCframes)
        end
    end
end

function sprofile_tree(io::IO, doCframes::Bool)
    bt, counts = sprof_tree()
    level = 0
    len = Int[length(x) for x in bt]
    keep = len .> 0
    sprofile_tree(io, bt[keep], counts[keep], level, doCframes)
end
sprofile_tree(io::IO) = sprofile_tree(io, false)
sprofile_tree(doCframes::Bool) = sprofile_tree(OUTPUT_STREAM, doCframes)
sprofile_tree() = sprofile_tree(OUTPUT_STREAM, false)

## Use this to profile code
macro sprofile(ex)
    if sprofile_maxlen_data() == 0
        # Initialize the profile data structures
        const nsamples = 1_000_000
        const delay = 1_000_000 # Have the timer fire every 1ms = 10^6ns
        sprofile_init(nsamples, delay)
    end        
    quote
        try
            status = sprofile_start_timer()
            if status < 0
                error(sprofile_error_codes[status])
            end
            $(esc(ex))
        finally
            sprofile_stop_timer()
        end
    end
end

# Utilities
function truncto(str::ASCIIString, w::Int)
    ret = str;
    if length(str) > w
        ret = string("...", str[end-w+4:end])
    end
    ret
end

function sprof_sortorder(bt::Vector{Any})
    comb = Array(ASCIIString, length(bt))
    for i = 1:length(bt)
        thisbt = bt[i]
        if !isempty(thisbt)
            comb[i] = @sprintf("%s:%s:%06d", thisbt[2], thisbt[1], thisbt[3])
        else
            comb[i] = "zzz"
        end
    end
    p = sortperm(comb)
end

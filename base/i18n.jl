module I18n

export locale

CALLBACKS = Function[]

function setlocale(category::Integer, locale::Union(ASCIIString,Ptr{None}))
    p = ccall(:setlocale, Ptr{Uint8}, (Int32, Ptr{Uint8}), category, locale)
    p == C_NULL ? p : bytestring(p)
end

function locale()
    setlocale(Base.JL_LC_CTYPE, C_NULL)
end

function locale(s::ByteString)
    setlocale(Base.JL_LC_ALL, s) == C_NULL && error("bad locale '$s'")
    for cb in CALLBACKS
        cb()
    end
end

end # module

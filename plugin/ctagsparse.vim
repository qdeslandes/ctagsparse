" Original work copyright (c) 2017 Junegunn Choi
" Modified work copyright (c) 2020 Quentin Deslandes
"
" MIT License
"
" Permission is hereby granted, free of charge, to any person obtaining
" a copy of this software and associated documentation files (the
" "Software"), to deal in the Software without restriction, including
" without limitation the rights to use, copy, modify, merge, publish,
" distribute, sublicense, and/or sell copies of the Software, and to
" permit persons to whom the Software is furnished to do so, subject to
" the following conditions:
"
" The above copyright notice and this permission notice shall be
" included in all copies or substantial portions of the Software.
"
" THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
" EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
" MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
" NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
" LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
" OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
" WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

let s:cpo_save = &cpo
set cpo&vim

let s:root_dir = expand('<sfile>:h:h')
let s:binary = (s:root_dir).'/bin/ctagsparse'

function! s:warn(message)
  echohl WarningMsg
  echom a:message
  echohl None
  return 0
endfunction

function! ctagsparse#sink(line)
  normal! m'
  try
    let [magic, &magic, wrapscan, &wrapscan, acd, &acd] = [&magic, 0, &wrapscan, 1, &acd, 0]
    try
      let parts   = split(a:line, '\t\zs')
      let excmd   = parts[2]
      let base    = fnamemodify(parts[-1], ':h')
      let relpath = parts[1][:-2]
      let abspath = relpath =~ '^/' ? relpath : join([base, relpath], '/')
      execute 'e' expand(abspath, 1)
      silent execute excmd
    catch /^Vim:Interrupt$/
      break
    catch
      call s:warn(v:exception)
    endtry
  finally
    let [&magic, &wrapscan, &acd] = [magic, wrapscan, acd]
  endtry
  normal! zz
endfunction

function! ctagsparse#tags(query)
  if !executable(s:binary)
    let ctagsparse_missing = 'ctagsparse missing, to fix it, run: make -C '.s:root_dir
    return s:warn(ctagsparse_missing)
  endif

  if empty(tagfiles())
      return s:warn('No tags found')
  endif

  let exclude_cmd = ''
  for exclude in get(g:, 'ctagsparse_exclude', [])
    let exclude_cmd = exclude_cmd.' -e '.exclude
  endfor

  let allow_cmd = ''
  for allow in get(g:, 'ctagsparse_allow', [])
    let allow_cmd = allow_cmd.' -a '.allow
  endfor

  for buffer in getbufinfo()
    let allow = buffer.name

    if buffer.name != ''
      let allow_cmd = allow_cmd.' -a '.allow
    endif
  endfor

  let ctagsparse_opts = exclude_cmd.' '.allow_cmd

  return fzf#run(fzf#wrap({
  \ 'source':  s:binary.' -v '.ctagsparse_opts.' '.join(map(tagfiles(), 'fzf#shellescape(fnamemodify(v:val, ":p"))')),
  \ 'sink':   function('ctagsparse#sink'),
  \ 'options': ['--nth', '1', '-m', '--tiebreak=begin', '-e', '+x', '+i', '+s', '--tac', '--prompt', 'CTagsParse> ', '--query', a:query]}))
endfunction

command! -nargs=0 CTagsParse     call ctagsparse#tags('')
command! -nargs=0 CTagsParseHere call ctagsparse#tags(expand("<cword>"))

let &cpo = s:cpo_save
unlet s:cpo_save
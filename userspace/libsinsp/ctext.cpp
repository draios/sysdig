#include "ctext.h"
#include <string.h>
#include <algorithm>		// std::max

using namespace std;

#ifndef _WIN32

const ctext_config config_default = {
	.m_buffer_size = CTEXT_DEFAULT_BUFFER_SIZE,
	.m_bounding_box = CTEXT_DEFAULT_BOUNDING_BOX,
	.m_do_wrap = CTEXT_DEFAULT_DO_WRAP,
	.m_append_top = CTEXT_DEFAULT_APPEND_TOP,
	.m_scroll_on_append = CTEXT_DEFAULT_SCROLL_ON_APPEND,
	.m_auto_newline = CTEXT_DEFAULT_AUTO_NEWLINE,
};

ctext::ctext(WINDOW *win, ctext_config *config)
{
	this->m_win = win;

	/*
	this->m_debug = new ofstream();
	this->m_debug->open("debug1.txt");
	*/

	this->m_do_draw = true;
	
	if(config) 
	{
		memcpy(&this->m_config, config, sizeof(ctext_config));
	} 
	else 
	{
		memcpy(&this->m_config, &config_default, sizeof(ctext_config));
	}

	this->m_pos_x = 0;
	this->m_pos_y = 0;

	this->m_max_y = 0;

	// initialized the buffer with the empty row
	this->add_row();
}

int8_t ctext::set_config(ctext_config *config)
{
	memcpy(&this->m_config, config, sizeof(ctext_config));
	return this->redraw();
}

int8_t ctext::get_config(ctext_config *config)
{
	memcpy(config, &this->m_config, sizeof(ctext_config));
	return 0;
}

int8_t ctext::attach_curses_window(WINDOW *win)
{
	this->m_win = win;
	return this->redraw();
}

int32_t ctext::putchar(int32_t c)
{
	return this->printf("%c", c);
}

int32_t ctext::clear(int32_t amount)
{
	int32_t ret = 0;
	if(amount == 0) 
	{
		ret = this->m_buffer.size();
		this->m_buffer.clear();
		this->add_row();
	}
	else if(this->m_buffer.size()) 
	{
		ret = this->m_buffer.size();
		this->m_buffer.erase(this->m_buffer.begin(), this->m_buffer.begin() + amount);
		ret -= this->m_buffer.size();
	}

	// We do the same logic when removing content
	// .. perhaps forcing things down or upward
	if(this->m_config.m_scroll_on_append)
	{
		this->get_win_size();
		// now we force it.
		this->direct_scroll(0, this->m_buffer.size() - this->m_win_height);
	}

	this->redraw();
	return ret;
}

int8_t ctext::ob_start()
{
	int8_t ret = this->m_do_draw;
	this->m_do_draw = false;
	return ret;
}

int8_t ctext::ob_end()
{
	int8_t ret = !this->m_do_draw;
	this->m_do_draw = true;
	this->redraw();
	return ret;
}

int8_t ctext::direct_scroll(int32_t x, int32_t y)
{
	if(this->m_config.m_bounding_box) 
	{
		y = min(y, (int32_t)(this->m_max_y - this->m_win_height));
		x = max(0, (int32_t)x);
		y = max(0, (int32_t)y);
	}

	this->m_pos_x = x;
	this->m_pos_y = y;

	return 0;
}

int8_t ctext::scroll_to(int32_t x, int32_t y)
{
	this->direct_scroll(x, y);
	return this->redraw();
}

int8_t ctext::get_offset(int32_t*x, int32_t*y)
{
	*x = this->m_pos_x;
	*y = this->m_pos_y;

	return 0;
}

int8_t ctext::get_offset_percent(float*percent)
{
	this->get_win_size();
	*percent = (float)(this->m_pos_y) / (this->m_max_y - this->m_win_height);

	return 0;
}

int8_t ctext::get_buf_size(int32_t*buf_size)
{
	*buf_size = this->m_max_y;

	return 0;
}

int32_t ctext::available_rows()
{
	// since our buffer clearing scheme permits us to overflow,
	// we have to bind this to make sure that we return >= 0 values
	return max(this->m_config.m_buffer_size - this->m_max_y - 1, 0);
}

int32_t ctext::up(int32_t amount) 
{
	return this->down(-amount);
}

int32_t ctext::down(int32_t amount) 
{
	return this->scroll_to(this->m_pos_x, this->m_pos_y + amount);
}

int32_t ctext::jump_to_first_line()
{
	int32_t current_line = this->m_pos_y;

	// now we try to scroll above the first
	// line.	the bounding box rule will
	// take care of the differences for us.
	this->scroll_to(this->m_pos_x, 0 - this->m_win_height + 1);

	return current_line - this->m_pos_y;
}

int32_t ctext::jump_to_last_line()
{
	int32_t current_line = this->m_pos_y;

	this->get_win_size();
	this->scroll_to(this->m_pos_x, this->m_max_y - 1);
	return current_line - this->m_pos_y;
}

int32_t ctext::page_down(int32_t page_count) 
{
	this->get_win_size();
	return this->down(page_count * this->m_win_height);
}

int32_t ctext::page_up(int32_t page_count) 
{
	this->get_win_size();
	return this->down(-page_count * this->m_win_height);
}

int32_t ctext::left(int32_t amount) 
{
	return this->right(-amount);
}

int32_t ctext::right(int32_t amount) 
{
	return this->scroll_to(this->m_pos_x + amount, this->m_pos_y);
}

void ctext::get_win_size() 
{
	int32_t width = 0, height = 0;

	if(this->m_win)
	{
		getmaxyx(this->m_win, height, width);
	}
	this->m_win_width = width;
	this->m_win_height = height;
}

int8_t ctext::rebuf()
{
	// memory management is expensive, so we only
	if((int32_t)this->m_buffer.size() > (this->m_config.m_buffer_size * 11 / 10))
	{
		this->m_buffer.erase(this->m_buffer.begin(), this->m_buffer.end() - this->m_config.m_buffer_size);
	}
	
	this->m_max_y = this->m_buffer.size() - 1;
	
	//
	// Since we've changed the bounding box of the content we have to
	// issue a rescroll on exactly our previous parameters. This may
	// force us inward or may retain our position.
	// 
	return this->direct_scroll(this->m_pos_x, this->m_pos_y);
}

void ctext::add_format_if_needed()
{
	attr_t attrs; 
	int16_t color_pair;

	if(!this->m_win) 
	{
		return;
	}

	if(this->m_buffer.empty())
	{
		return;
	}

	// get the most current row.
	ctext_row *p_row = &this->m_buffer.back();

	ctext_format p_format = {0,0,0};
	if(!p_row->format.empty()) 
	{
		// and the most current format
		p_format = p_row->format.back();
	} 

	wattr_get(this->m_win, &attrs, &color_pair, 0);

	if(attrs != p_format.attrs || color_pair != p_format.color_pair)
	{
		// our properties have changed so we need to record this.
		ctext_format new_format = 
		{
			// this is our offset
			.offset = (int32_t)p_row->data.size(),

			.attrs = attrs,
			.color_pair = color_pair
		};

		//*this->m_debug << "fmt:" << row_ix  << " " << new_format.offset << " " << new_format.color_pair << " " << new_format.attrs << "OV" << endl;
		// if the new thing we are adding has the same
		// offset as the previous, then we dump the
		// previous.
		if(p_format.offset == new_format.offset && !p_row->format.empty())
		{
			p_row->format.pop_back();
		}
		p_row->format.push_back(new_format);
	}
}

ctext_row* ctext::add_row()
{
	ctext_row row;

	// if there is an exsting line, then
	// we carry over the format from the
	// last line..
	if(!this->m_buffer.empty())
	{
		ctext_row p_row = this->m_buffer.back();

		if(!p_row.format.empty()) 
		{
			ctext_format p_format( p_row.format.back() );

			// set the offset to the initial.
			//*this->m_debug << "fmt:" << row_ix  << " " << p_format.offset << " " << p_format.color_pair << " " << p_format.attrs << "|" << endl;
			p_format.offset = 0;
			row.format.push_back(p_format);
		}
	}

	row.data = "";

	this->m_buffer.push_back(row);

	return &this->m_buffer.back();
}

char* next_type(char* search, const char delim) 
{
	while(*search && *search != delim)
	{
 		search ++;
	}
	return search;
}

int8_t ctext::vprintf(const char*format, va_list ap)
{
	char *p_line, *n_line;
	char large_buffer[CTEXT_BUFFER_SIZE] = {0};

	this->add_format_if_needed();
	ctext_row *p_row = &this->m_buffer.back();

	vsnprintf(large_buffer, CTEXT_BUFFER_SIZE, format, ap);

	if(this->m_config.m_auto_newline && strlen(large_buffer) < (CTEXT_BUFFER_SIZE - 1))
	{
		sprintf(large_buffer + strlen(large_buffer), "\n");
	}

	p_line = large_buffer;
	do 
  {
		n_line = next_type(p_line, '\n');

		string wstr(p_line, n_line - p_line);
		p_row->data += wstr;

		if(*n_line)
		{
			p_row = this->add_row();
		}
		p_line = n_line + 1;
	} 
  while (*n_line);

	
	// Since we are adding content we need to see if we are
	// to force on scroll.
	if(this->m_config.m_scroll_on_append)
	{
		this->get_win_size();
		// now we force it.
		this->direct_scroll(0, this->m_buffer.size() - this->m_win_height);
	}

	return this->redraw();
}

int cprintf(ctext*win, const char *format, ...)
{
	int ret;
	va_list args;
	va_start(args, format);
	ret = win->vprintf(format, args);
	va_end(args);
	return ret;
}

int8_t ctext::printf(const char*format, ...)
{
	int8_t ret;

	va_list args;
	va_start(args, format);
	ret = this->vprintf(format, args);

	va_end(args);
	return ret;
}

int8_t ctext::nprintf(const char*format, ...)
{
	int8_t ret;
	va_list args;

	// first turn off the rerdaw flag
	this->ob_start();

	// then call the variadic version
	va_start(args, format);
	ret = this->vprintf(format, args);

	va_end(args);

	//
	// then manually untoggle the flag
	// (this is necessary because ob_end
	// does TWO things, breaking loads of
	// anti-patterns I'm sure.)
	//
	this->m_do_draw = true;

	return ret;
}

int8_t ctext::redraw() 
{
	// Bail out if we aren't supposed to draw
	// this time.
	// Calculate the bounds of everything first.
	this->rebuf();
	if(!this->m_do_draw)
	{
		return 0;
	}

	if(!this->m_win)
	{
		// Not doing anything without a window.
		return -1;
	}

	attr_t res_attrs; 
	int16_t res_color_pair;
	wattr_get(this->m_win, &res_attrs, &res_color_pair, 0);
	wattr_off(this->m_win, COLOR_PAIR(res_color_pair), 0);
	
	this->get_win_size();

	//
	// By this time, if we are bounded by a box,
	// it has been accounted for.
	//
	// Really our only point of interest is
	// whether we need to append to bottom
	// or append to top.
	//
	// We will assume that we can
	// populate the window quick enough
	// to avoid linear updating or paging.
	//	... it's 2015 after all.
	//
	werase(this->m_win);

	// Regardless of whether this is append to top
	// or bottom we generate top to bottom.

	int32_t start_char = max(0, (int32_t)this->m_pos_x);
	int32_t buf_offset = start_char;
	// the endchar will be in the substr
	
	//
	// We start as m_pos_y in our list and move up to
	// m_pos_y + m_win_height except in the case of 
	// wrap around.  Because of this special case,
	// we compute when to exit slightly differently.
	//
	// This is the current line of output, which stays
	// below m_win_height
	//
	int32_t line = 0;

	// start at the beginning of the buffer.
	int32_t index = this->m_pos_y;
	int32_t directionality = +1;
	int32_t cutoff;
	int32_t num_added = 0;
	int32_t win_offset = 0;
	bool b_format = false;
	string to_add;
	ctext_row *p_source;
	vector<ctext_format>::iterator p_format;

	// if we are appending to the top then we start
	// at the end and change our directionality.
	if(this->m_config.m_append_top)
	{
		directionality = -1;
		index = this->m_pos_y + this->m_win_height - 1;
	}

	while(line <= this->m_win_height)
	{
		wredrawln(this->m_win, line, 1);
		
		if((index < this->m_max_y) && (index >= 0))
		{
			// We only index into the object if we have the
			// data to do so.
			p_source = &this->m_buffer[index];
			p_format = p_source->format.begin();

			// Reset the offset.
			win_offset = -min(0, (int32_t)this->m_pos_x);
			buf_offset = start_char;

			for(;;) 
			{
				// our initial cutoff is the remainder of window space
				// - our start
				cutoff = this->m_win_width - win_offset;
				b_format = false;

				// move the cursor before doing anything.
				//wmove(this->m_win, line, win_offset);

				wstandend(this->m_win);
				// if we have a format to account for and we haven't yet,
				if(!p_source->format.empty() && p_format->offset <= buf_offset)
				{
					// then we add it 
					//mvwchgat
					wattr_set(this->m_win, p_format->attrs, p_format->color_pair, 0);//p_format->color_pair), 0);
					//this->cattr_on(p_format->color_pair);//p_format->color_pair), 0);

					// and tell ourselves below that we've done this.
					b_format = true;

					// see if there's another cutoff point
					if((p_format + 1) != p_source->format.end())
					{
						// If it's before our newline then we'll have to do something
						// with with that.
						//
						// The first one is the characters we are to print this time,
						// the second is how many characters we would have asked for
						// if there was no format specified.
						cutoff = min((p_format + 1)->offset - buf_offset, (int32_t)cutoff); 
					}
				}

				// if we can get that many characters than we grab them
				// otherwise we do the empty string
				if(buf_offset < (int32_t)p_source->data.size())
				{
					to_add = p_source->data.substr(buf_offset, cutoff);

					mvwaddstr(this->m_win, line, win_offset, to_add.c_str());
				}
				else
				{
					to_add = "";
				}

				// This is the number of characters we've placed into
				// the window.
				num_added = to_add.size();
				buf_offset += num_added;

				// See if we need to reset our format
				if(b_format) 
				{
					// If the amount of data we tried to grab is less than
					// the width of the window - win_offset then we know to
					// turn off our attributes

					// and push our format forward if necessary
					if( (p_format + 1) != p_source->format.end() &&
							(p_format + 1)->offset >= buf_offset 
						)
					{
						p_format ++;
					}
				}

				// if we are at the end of the string, we break out
				if((int32_t)p_source->data.size() <= buf_offset || (num_added == 0 && p_source->data.size() > 0))
				{
					break;
				}

				// otherwise, move win_offset forward
				win_offset += num_added;
				
				// otherwise, if we are wrapping, then we do that here.
				if(win_offset == this->m_win_width)
				{
					// if we've hit the vertical bottom
					// of our window then we break out
					// of this
					//
					// otherwise if we are not wrapping then
					// we also break out of this
					if(line == this->m_win_height || !this->m_config.m_do_wrap )
					{
						break;
					}

					// otherwise move our line forward
					line++;

					// we reset the win_offset back to its
					// initial state
					win_offset = 0;

					// and we loop again.
				}
			}
		}
		index += directionality;
		line++;
	}

	wrefresh(this->m_win);
	wattr_set(this->m_win, res_attrs, res_color_pair, 0);

	return 0;
}

#endif // _WIN32

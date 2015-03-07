#include "ctext.h"
#include <string.h>
#include <algorithm>		// std::max

using namespace std;

const ctext_config config_default = {
	.m_buffer_size = CTEXT_DEFAULT_BUFFER_SIZE,
	.m_bounding_box = CTEXT_DEFAULT_BOUNDING_BOX,
	.m_do_wrap = CTEXT_DEFAULT_DO_WRAP,
	.m_append_top = CTEXT_DEFAULT_APPEND_TOP,
	.m_scroll_on_append = CTEXT_DEFAULT_SCROLL_ON_APPEND,
	.m_auto_newline = CTEXT_DEFAULT_AUTO_NEWLINE,
	.m_on_event = CTEXT_DEFAULT_ON_EVENT
};

ctext::ctext(WINDOW *win, ctext_config *config)
{
	this->m_win = win;
	this->m_debug = new ofstream();
	this->m_debug->open("debug.txt");
	
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

	this->m_max_x = 0;
	this->m_max_y = 0;

	// initialized the buffer with the empty row
	this->add_row();
}

int8_t ctext::set_config(ctext_config *config)
{
	memcpy(&this->m_config, config, sizeof(ctext_config));

	if (this->m_config.m_on_event)
	{
		this->m_config.m_on_event(this, CTEXT_CONFIG);
	}

	return this->render();
}

int8_t ctext::get_config(ctext_config *config)
{
	memcpy(config, &this->m_config, sizeof(ctext_config));
	return 0;
}

int8_t ctext::attach_curses_window(WINDOW *win)
{
	this->m_win = win;
	return this->render();
}

int32_t ctext::putchar(int32_t c)
{
	return this->printf("%c", c);
}

int16_t ctext::clear(int16_t amount)
{
	int16_t ret = 0;
	if(amount == 0) 
	{
		ret = this->m_buffer.size();
		this->m_buffer.clear();
	}
	else
	{
		if(this->m_buffer.size()) 
		{
			ret = this->m_buffer.size();
			this->m_buffer.erase(this->m_buffer.begin(), this->m_buffer.begin() + amount);
			ret -= this->m_buffer.size();
		}
	}

	if (this->m_config.m_on_event)
	{
		this->m_config.m_on_event(this, CTEXT_CLEAR);
	}

	// We do the same logic when removing content
	// .. perhaps forcing things down or upward
	if(this->m_config.m_scroll_on_append)
	{
		this->get_win_size();
		// now we force it.
		this->direct_scroll(0, this->m_buffer.size() - this->m_win_height);
	}

	this->render();
	return ret;
}

int8_t ctext::direct_scroll(int16_t x, int16_t y)
{
	if(this->m_config.m_bounding_box) 
	{
		x = max(0, (int32_t)x);
		y = max(0, (int32_t)y);
		x = min(x, (int16_t)(this->m_max_x - this->m_win_width));
		y = min(y, (int16_t)(this->m_max_y - this->m_win_height));
	}

	this->m_pos_x = x;
	this->m_pos_y = y;

	if (this->m_config.m_on_event)
	{
		this->m_config.m_on_event(this, CTEXT_SCROLL);
	}

	return 0;
}

int8_t ctext::scroll_to(int16_t x, int16_t y)
{
	this->direct_scroll(x, y);
	return this->render();
}

int8_t ctext::get_offset(int16_t*x, int16_t*y)
{
	*x = this->m_pos_x;
	*y = this->m_pos_y;

	return 0;
}

int8_t ctext::get_size(int16_t*x, int16_t*y)
{
	*x = this->m_max_x;
	*y = this->m_max_y;

	return 0;
}

int16_t ctext::up(int16_t amount) 
{
	return this->down(-amount);
}

int16_t ctext::down(int16_t amount) 
{
	return this->scroll_to(this->m_pos_x, this->m_pos_y + amount);
}

int16_t ctext::left(int16_t amount) 
{
	return this->right(-amount);
}

int16_t ctext::right(int16_t amount) 
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
	this->get_win_size();

	if((int16_t)this->m_buffer.size() > this->m_config.m_buffer_size)
	{
		this->m_buffer.erase(this->m_buffer.begin(), this->m_buffer.end() - this->m_config.m_buffer_size);
	}
	
	this->m_max_x = 0;	

	//
	// Now unfortunately we have to do a scan over everything in N time to find
	// the maximum length string --- but only if we care about the bounding
	// box
	//
	if(this->m_config.m_bounding_box)
	{
		for(ctext_buffer::const_iterator it = this->m_buffer.begin(); it != this->m_buffer.end(); it++) 
		{
			this->m_max_x = max((int)this->m_max_x, (int)(*it).data.size());
		}
	}
 
	this->m_max_y = this->m_buffer.size();
	
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

		p_row->format.push_back(new_format);
//		wattr_off(this->m_win, COLOR_PAIR(color_pair), 0);
	}
}

void ctext::add_row()
{
	ctext_row row;
	row.format.clear();

	// if there is an exsting line, then
	// we carry over the format from the
	// last line..
	if(!this->m_buffer.empty())
	{
		ctext_row p_row = this->m_buffer.back();

		if(!p_row.format.empty()) 
		{
			ctext_format p_format( *p_row.format.end() );

			// set the offset to the initial.
			p_format.offset = 0;
			*this->m_debug << "(" << p_format.color_pair << " " << p_format.attrs << ")" << endl;
			//row.format.push_back(p_format);
		}
	}

	row.data = string("");

	this->m_buffer.push_back(row);
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

int8_t ctext::vprintf(const char*format, va_list ap)
{
	// strtok is bullshit and this is needed.
	bool should_newline = false;
	int8_t ret;
	char *p_line;
	char large_buffer[CTEXT_BUFFER_SIZE] = {0};

	this->add_format_if_needed();
	ctext_row *p_row = &this->m_buffer.back();

	memset(large_buffer, 0, CTEXT_BUFFER_SIZE);
	vsnprintf(large_buffer, CTEXT_BUFFER_SIZE, format, ap);

	if(this->m_config.m_auto_newline && strlen(large_buffer) < (CTEXT_BUFFER_SIZE - 1))
	{
		sprintf(large_buffer + strlen(large_buffer), "\n");
	}
	should_newline = (large_buffer[strlen(large_buffer) - 1] == '\n');

	p_line = strtok(large_buffer, "\n");
	if(p_line)
	{
		string wstr(p_line, p_line + strlen(p_line));
		p_row->data += wstr;

		*this->m_debug << p_row->data.c_str() << endl;

	}
	// this case is a single new line.
	else
	{
		this->add_row();
	}

	if (this->m_config.m_on_event)
	{
		this->m_config.m_on_event(this, CTEXT_DATA);
	}
	
	// Since we are adding content we need to see if we are
	// to force on scroll.
	if(this->m_config.m_scroll_on_append)
	{
		this->get_win_size();
		// now we force it.
		this->direct_scroll(0, this->m_buffer.size() - this->m_win_height);
	}

	ret = this->render();

	while(p_line)
	{
		p_line = strtok(0, "\n");
		if(p_line)
		{
			// this means we have encountered a new line and must push our
			// buffer forward
			this->add_row();
			ret = this->printf(p_line);
		} 
		else if(should_newline)
		{
			this->add_row();
		}
	}
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

void next_line(WINDOW *win, int16_t*line)
{
	//wredrawln(win, max(*line - 1, 0), *line + 1);
	(*line)++;
}

int8_t ctext::render() 
{

	// Calculate the bounds of everything first.
	this->rebuf();

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

	int16_t start_char = max(0, (int32_t)this->m_pos_x);
	int16_t buf_offset = start_char;
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
	int16_t line = 0;

	// start at the beginning of the buffer.
	int16_t index = this->m_pos_y;
	int16_t directionality = +1;
	int16_t cutoff;
	int16_t num_added = 0;
	int16_t win_offset = 0;
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

	//*this->m_debug << "Start ---" << endl;
	while(line <= this->m_win_height)
	{
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

				// if we have a format to account for and we haven't yet,
				if(!p_source->format.empty() && p_format->offset <= buf_offset)
				{
					// then we add it 
					//*this->m_debug << "on" << p_format->color_pair <<  " ";
					wattr_on(this->m_win, COLOR_PAIR(p_format->color_pair),0);//p_format->color_pair), 0);

					// and tell ourselves below that we've done this.
					b_format = true;

					// see if there's another cutoff point
					if(p_format != p_source->format.end())
					{
						// if it's before our newline then we'll have to do something
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
				to_add = (buf_offset < (int16_t)p_source->data.size()) ?
					p_source->data.substr(buf_offset, cutoff) :
					string("");

				mvwaddstr(this->m_win, line, win_offset, to_add.c_str());
				//*this->m_debug << "printed";

				// this is the number of characters we've placed into
				// the window.
				num_added = to_add.size();
				buf_offset += num_added;

				// See if we need to reset our format
				if(b_format) 
				{
					// If the amount of data we tried to grab is less than
					// the width of the window - win_offset then we know to
					// turn off our attributes
					//*this->m_debug << "off" << p_format->color_pair << endl;
					wattr_off(this->m_win, COLOR_PAIR(p_format->color_pair),0);//p_format->color_pair), 0);

					// and push our format forward if necessary
					if( p_format != p_source->format.end() &&
							(p_format + 1)->offset >= buf_offset 
						)
					{
						p_format ++;
					}
				}

				// if we are at the end of the string, we break out
				if((int16_t)p_source->data.size() <= buf_offset)
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
					next_line(this->m_win, &line);

					// we reset the win_offset back to its
					// initial state
					win_offset = 0;

					// and we loop again.
				}
			}
		}
		index += directionality;
		next_line(this->m_win, &line);
	}

	wrefresh(this->m_win);
	wattr_set(this->m_win, res_attrs, res_color_pair, 0);

	return 0;
}
